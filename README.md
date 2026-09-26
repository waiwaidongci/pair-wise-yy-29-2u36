# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议、撤销快照和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、撤销名单快照离线核验、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式；请求体带 `snapshot` 时走撤销快照离线核验。
- `POST /api/snapshots`：签发方发布撤销名单快照，可指定 `ttl_seconds`（默认 86400，范围 60–604800）。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态（含各签发方快照版本范围与当前可用性）和健康检查。

## 撤销名单快照（断网考点离线核验）

签发方通过 `POST /api/snapshots` 发布快照：版本号按签发方单调递增，含生成时间、过期时间和基于当前密钥版本的 HMAC 签名，名单条目为发布时点已撤销凭证及其 `revocation_effective_at`。

断网考点核验时在 `POST /api/verify` 请求体中带上快照与核验时刻 `at`：

- 快照过期、版本倒退（低于本地已见的该签发方最新版本）或签名不符：返回 `status=pending_online`、`valid=null`，停在待联网复核，不给出有效结论。
- 快照有效且名单命中：核验时刻不早于生效时刻返回 `revoked`，否则 `valid_until_revocation`。
- 快照有效且未命中：返回 `valid_snapshot`（凭证自身过期仍返回 `expired`）。

页面与 `GET /api/state` 的 `snapshots` 字段展示每个签发方的版本范围（min–max）、最新快照生成/过期时间和当前是否可用。

## 代码结构

- `app.py`：HTTP 接口、凭证签发/撤销/争议/在线核验。
- `snapshot_publisher.py`：名单生成（版本、签名、发布）。
- `snapshot_verifier.py`：核验判定（快照校验、按生效时刻拒绝、待联网复核）。
- `snapshot_store.py`：快照持久化与版本范围/可用性查询。
- `common.py`：共享的时间与规范化编码辅助函数。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线核验依赖未过期且未倒退的撤销快照，过期或存疑时必须联网复核；也未实现可验证凭证联盟标准或硬件密钥保护。
