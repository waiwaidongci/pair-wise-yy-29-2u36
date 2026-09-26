import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import CredentialService, Store
from common import iso, now
from snapshot_publisher import SnapshotPublisher
from snapshot_store import SnapshotStore
from snapshot_verifier import SnapshotVerifier


class RevocationSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.service = CredentialService(self.store)
        self.snapshots = SnapshotStore(self.store)
        self.publisher = SnapshotPublisher(self.store, self.snapshots)
        self.verifier = SnapshotVerifier(self.service, self.snapshots)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}], 365
        )
        self.credential = self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-1")
        self.proof = self.service.present("alice", "holder", self.credential["id"], ["name"])

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def publish(self, **kwargs):
        return self.publisher.publish("issuer-a", "issuer", "issuer-a", **kwargs)

    def test_snapshot_roundtrip_and_revocation_by_effective_time(self):
        snapshot = json.loads(json.dumps(self.publish()))
        self.assertEqual(1, snapshot["version"])
        self.assertEqual("valid_snapshot", self.verifier.verify(self.proof["token"], snapshot)["status"])
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "学历造假", effective_at=iso(now() - timedelta(hours=1)))
        snapshot = self.publish()
        self.assertEqual(2, snapshot["version"])
        self.assertEqual(1, len(snapshot["entries"]))
        result = self.verifier.verify(self.proof["token"], snapshot)
        self.assertEqual("revoked", result["status"])
        self.assertFalse(result["valid"])

    def test_future_effective_revocation_valid_until_effective(self):
        effective = iso(now() + timedelta(hours=1))
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "延迟生效", effective_at=effective)
        snapshot = self.publish()
        result = self.verifier.verify(self.proof["token"], snapshot)
        self.assertEqual("valid_until_revocation", result["status"])
        self.assertEqual(effective, result["revocation_starts_at"])
        after = self.verifier.verify(self.proof["token"], snapshot, at=iso(now() + timedelta(hours=2)))
        self.assertEqual("revoked", after["status"])

    def test_expired_regressed_and_forged_snapshots_stay_pending(self):
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "学历造假")
        snapshot = self.publish(ttl_seconds=60)
        expired = self.verifier.verify(self.proof["token"], snapshot, at=iso(now() + timedelta(hours=2)))
        self.assertEqual("pending_online", expired["status"])
        self.assertIsNone(expired["valid"])
        self.assertIn("过期", expired["reason"])
        self.publish()
        regressed = self.verifier.verify(self.proof["token"], snapshot)
        self.assertEqual("pending_online", regressed["status"])
        self.assertIsNone(regressed["valid"])
        self.assertIn("版本倒退", regressed["reason"])
        forged = dict(snapshot)
        forged["entries"] = []
        tampered = self.verifier.verify(self.proof["token"], forged)
        self.assertEqual("pending_online", tampered["status"])
        self.assertIsNone(tampered["valid"])
        self.assertIn("签名", tampered["reason"])

    def test_status_reports_version_range_and_usability(self):
        self.publish(ttl_seconds=3600)
        self.publish(ttl_seconds=3600)
        status = self.snapshots.status()
        self.assertEqual(1, len(status))
        row = status[0]
        self.assertEqual("issuer-a", row["issuer"])
        self.assertEqual(1, row["min_version"])
        self.assertEqual(2, row["max_version"])
        self.assertEqual(2, row["snapshot_count"])
        self.assertTrue(row["usable_now"])


if __name__ == "__main__":
    unittest.main()
