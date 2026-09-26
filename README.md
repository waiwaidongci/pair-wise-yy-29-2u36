# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议、撤销快照和审计记录。服务支持最少字段披露、带签名撤销快照的离线核验、密钥轮换和证件状态争议。

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
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式；离线时可附带撤销快照令牌。
- `POST /api/snapshots`：签发方发布撤销快照（版本号、生成时间、过期时间、签名），返回可分发的快照令牌。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 撤销快照与断网核验

断网考点无法实时查询撤销状态，核验时需携带签发方发布的撤销快照：

- 签发方通过 `POST /api/snapshots` 生成名单，版本号按签发方单调递增，名单含生成时间、过期时间和签名，条目为已撤销凭证及其生效时刻。
- 离线核验（`online=false`）时在请求体带上 `snapshot` 快照令牌与核验时刻 `at`。
- 快照过期、版本倒退（低于已知最新版本）或签名不符时，结果停留 `pending_online`（`valid=null`），不出具有效结论，需联网复核。
- 快照覆盖到的已撤销凭证按名单中的生效时刻拒绝：核验时刻不早于生效时刻判定 `revoked`，否则 `valid_until_revocation`；未覆盖的凭证判定 `valid_offline`。
- `GET /api/state` 与首页展示每个签发方的版本范围及最新快照当前是否可用。

## 文件结构

- `app.py`：HTTP 接口与业务流程编排。
- `revocation_snapshot.py`：撤销名单生成（收集撤销条目、签名、发布新版本）。
- `snapshot_verify.py`：离线核验判定（快照校验与撤销结论）。
- `snapshot_store.py`：撤销快照持久化与版本范围查询。
- `credential_utils.py`：共享的时间、编码与签名信封工具。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中；离线核验只能信赖随附的撤销快照，争议处理与快照之外的状态仍需在线确认；也未实现可验证凭证联盟标准或硬件密钥保护。
