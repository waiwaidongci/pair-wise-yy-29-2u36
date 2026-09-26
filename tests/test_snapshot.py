import base64
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ApiError, CredentialService, Store
from credential_utils import iso, now


class RevocationSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}], 365,
        )

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _issue_and_present(self, holder, idempotency_key):
        credential = self.service.issue("issuer-a", "issuer", self.template["id"], holder, {"name": holder, "degree": "BSc"}, idempotency_key)
        proof = self.service.present(holder, "holder", credential["id"], None)
        return credential, proof

    def test_offline_verify_uses_snapshot_entries(self):
        credential, proof = self._issue_and_present("alice", "issue-1")
        snap_v1 = self.service.publish_snapshot("issuer-a", "issuer", "issuer-a")
        self.assertEqual(1, snap_v1["version"])
        result = self.service.verify(proof["token"], online=False, snapshot=snap_v1["token"])
        self.assertEqual("valid_offline", result["status"])
        self.assertEqual("ok", result["snapshot"]["status"])
        self.assertEqual(1, result["snapshot"]["version"])

        self.service.revoke("issuer-a", "issuer", credential["id"], "学位作废")
        stale = self.service.verify(proof["token"], online=False, snapshot=snap_v1["token"])
        self.assertEqual("valid_offline", stale["status"])  # 旧名单尚未覆盖该撤销

        snap_v2 = self.service.publish_snapshot("issuer-a", "issuer", "issuer-a")
        self.assertEqual(2, snap_v2["version"])
        revoked = self.service.verify(proof["token"], online=False, snapshot=snap_v2["token"])
        self.assertEqual("revoked", revoked["status"])
        self.assertFalse(revoked["valid"])
        self.assertEqual("学位作废", revoked["reason"])

        regressed = self.service.verify(proof["token"], online=False, snapshot=snap_v1["token"])
        self.assertEqual("pending_online", regressed["status"])
        self.assertIsNone(regressed["valid"])
        self.assertEqual("version_regressed", regressed["snapshot"]["status"])

    def test_snapshot_expired_and_effective_time(self):
        credential, proof = self._issue_and_present("bob", "issue-2")
        effective = iso(now() + timedelta(hours=2))
        self.service.revoke("issuer-a", "issuer", credential["id"], "资格取消", effective_at=effective)
        snapshot = self.service.publish_snapshot("issuer-a", "issuer", "issuer-a", 24)

        before = self.service.verify(proof["token"], online=False, snapshot=snapshot["token"])
        self.assertEqual("valid_until_revocation", before["status"])
        self.assertEqual(effective, before["revocation_starts_at"])

        after = self.service.verify(proof["token"], at=iso(now() + timedelta(hours=3)), online=False, snapshot=snapshot["token"])
        self.assertEqual("revoked", after["status"])

        expired = self.service.verify(proof["token"], at=iso(now() + timedelta(hours=25)), online=False, snapshot=snapshot["token"])
        self.assertEqual("pending_online", expired["status"])
        self.assertIsNone(expired["valid"])
        self.assertEqual("expired", expired["snapshot"]["status"])

    def test_snapshot_signature_and_issuer_mismatch(self):
        credential, proof = self._issue_and_present("carol", "issue-3")
        self.service.revoke("issuer-a", "issuer", credential["id"], "考试作弊")
        snapshot = self.service.publish_snapshot("issuer-a", "issuer", "issuer-a")

        envelope = json.loads(base64.urlsafe_b64decode(snapshot["token"] + "=" * (-len(snapshot["token"]) % 4)))
        envelope["payload"]["entries"] = []  # 篡改名单内容但保留原签名
        tampered = base64.urlsafe_b64encode(json.dumps(envelope).encode()).decode().rstrip("=")
        result = self.service.verify(proof["token"], online=False, snapshot=tampered)
        self.assertEqual("pending_online", result["status"])
        self.assertIsNone(result["valid"])
        self.assertEqual("signature_invalid", result["snapshot"]["status"])

        self.service.rotate_key("issuer-b", "issuer", "issuer-b")
        other = self.service.publish_snapshot("issuer-b", "issuer", "issuer-b")
        mismatch = self.service.verify(proof["token"], online=False, snapshot=other["token"])
        self.assertEqual("pending_online", mismatch["status"])
        self.assertEqual("issuer_mismatch", mismatch["snapshot"]["status"])

    def test_publish_permissions_and_state_summary(self):
        with self.assertRaises(ApiError):
            self.service.publish_snapshot("issuer-a", "holder", "issuer-a")
        with self.assertRaises(ApiError):
            self.service.publish_snapshot("issuer-b", "issuer", "issuer-a")
        first = self.service.publish_snapshot("issuer-a", "issuer", "issuer-a")
        second = self.service.publish_snapshot("issuer-a", "issuer", "issuer-a", 1)
        self.assertEqual((1, 2), (first["version"], second["version"]))
        snapshots = self.service.state()["snapshots"]
        self.assertEqual(1, len(snapshots))
        summary = snapshots[0]
        self.assertEqual("issuer-a", summary["issuer"])
        self.assertEqual(1, summary["min_version"])
        self.assertEqual(2, summary["latest_version"])
        self.assertEqual(2, summary["count"])
        self.assertTrue(summary["usable_now"])


if __name__ == "__main__":
    unittest.main()
