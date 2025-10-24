# Authn Domain

本目录定义认证（Authn）领域模型的核心实体与约定，用于与上层 service/repository 交互。

当前内容（已完成 / 已放置）：
- `account.go`：`Account` 结构体（含 `PrimaryCredentialID`、状态枚举、时间字段、metadata），带 GORM tag，表名 `accounts`。
- `profile.go`：`Profile` 结构体（用户可展示信息、avatar、locale、data jsonb），带 GORM tag，表名 `profiles`。
- `credential.go`：通用 `Credential` 结构体（kind/email/phone/oauth/password/passkey 等），包含 `key/normalized_key/provider/secret_hash/secret_enc/meta/verified_at/is_primary` 等字段，带 GORM tag，表名 `credentials`。

设计要点（摘要）：
- 将 Account（主体）与 Profile（展示资料）分离，凭证统一放在 `credentials` 表，支持多凭证 -> 单 account 的关系。
- `PrimaryCredentialID` 用于缓存首选联系方式（便于发送通知、密码找回、展示），真正主标记可在 `credentials.is_primary` 或 account 字段上维护，但必须保证事务一致性。
- 敏感数据处理：密码/refresh token 只存不可逆 `secret_hash`；若需保存第三方 token，请使用 KMS 加密后存入 `secret_enc` 并设置 TTL。
- 部分唯一索引（如“同一 tenant 下已验证的 email 唯一”）无法用 GORM tag 表达，必须在数据库 migration SQL 中创建（示例已在代码注释中给出）。

当前状态评估：
- 领域模型结构体与 GORM 标签已补全（核心字段、表名、常用索引 tag）。
- 尚未包含：repository 接口、迁移 SQL（db/migrations）、单元测试、以及 service 层使用示例。

下一步建议（可选，按优先级）：
1) 生成 Postgres 专用的 migration SQL（创建表、索引、partial unique index、扩展如 citext）并放入 `db/migrations/`。
2) 在 `internal/authn/repository` 下生成 GORM 风格 repository 接口与基础实现（包括按 `kind/normalized_key`、`account_id` 的查找方法）。
3) 为 `service` 层生成示例用例（注册、绑定凭证、设置主凭证、登录流程）并包含事务示例与审计调用点。
4) 编写单元测试与 integration test（使用 testcontainer 或本地 Postgres）。

假设与前提：
- 假设项目最终仅支持 PostgreSQL（推荐），以便使用 jsonb、partial unique index、citext 等特性；如需多 DB 支持需额外设计迁移策略。

如果你同意，我可以立即：
- 生成首批 `db/migrations` SQL（accounts/profiles/credentials + 建议索引与 partial unique index）并提供 `cmd/migrate` 示例；或
- 生成 `internal/authn/repository` 的接口与 GORM 实现骨架。

请告诉我下一步要执行哪一项（只需写序号或简单描述）。
