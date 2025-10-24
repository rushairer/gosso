
总体上你的设计思路很合理：把 account（用户主体）与 profile（详细信息）拆分、把不同登录方式单独建表并与 account 建多对一关系，符合“身份与凭证分离”的最佳实践。下面给出具体评估、改进建议、模型细节、约束与索引建议、常见流程（注册/绑定/合并/注销）以及一个可直接参考的 SQL 表结构草案，帮助你把设计做得更健壮、安全且易扩展。

一、总体评估（简要）
- 优点
  - 将 account 与 profile 分离，便于不同服务读取不同粒度数据（隐私与性能）。
  - 将各种认证凭证（email/phone/oauth）独立建表，便于扩展多种登录方式并支持绑定/解绑。
  - 支持“多对一”（多种方式对应同一 account），便于 account 合并与统一管理。
- 需要关注的点
  - 凭证表需要记录验证状态、验证时间与过期/撤销信息。
  - 第三方 OAuth 表不要长期保存敏感 access_token/refresh_token（或加密且缩短保存时长）。
  - 需考虑唯一性约束（例如同一邮箱只能被一个已验证的 account 使用），以及多租户/tenant 的隔离。
  - 要支持账号合并、冲突解决与审计追踪。

二、推荐的改进要点（要做的／优先）
1. 增加一张通用的 auth_method 表或 credential 表作为抽象（可选）
   - 好处：统一管理各种登录方式的元信息（kind: email/phone/oauth/password/passkey），方便扩展新方式而无需每次建新表。
2. 明确字段：在凭证表中保存 verified_at、verified_by（可选）、status（active/disabled/revoked）、last_used_at。
3. 第三方 oauth 表只保存最小需要的字段（provider, provider_user_id, linked_at, scopes）。access_token、refresh_token 若必须保存应加密并有 TTL。
4. password（若存在）应放在 credential 表或 passwords 表，保存 hash、salt、algorithm、updated_at、failed_attempts。
5. 支持软删除（deleted_at），并保留 audit 日志。
6. 支持 account 外键与 tenant_id（如多租户场景）。
7. 为性能设计适当索引（email、phone、provider+provider_user_id、account_id、tenant_id）。
8. 支持事务与幂等操作（注册、绑定、合并必须在事务中处理并记录事件）。
9. 记录审计事件（谁、何时、何操作）——比如 authn/task 或 internal/audit 保存这些记录。
10. 考虑 GDPR：用户可要求导出/删除数据，需要设计可追踪数据位置与脱敏/匿名化策略。

三、常见流程（简化）
- 新访客用邮箱验证码登录（自动创建账号）
  1) 收到邮箱，校验验证码（短期有效）；若邮箱对应的已验证 credential，则登录到对应 account。
  2) 否则在事务中创建 account + profile + email credential（verified_at = now），记录 audit。
- 第三方登录（OAuth）
  1) 用 provider_user_id 查找 oauth credential -> 若存在且绑定 account -> 登录。
  2) 否则创建新 account（或提示绑定已有账号），创建 oauth credential（linked_at）。
  3) 不建议将 provider 的 long-lived tokens 长期存储，若存储要加密并设置 TTL。
- 绑定新方式（用户已登录）
  1) 检查目标凭证是否已被其他 account 使用（冲突处理策略）。
  2) 在事务中创建 credential，并将其指向当前 account，记录 audit。
- 合并账号
  - 提供手动（用户请求）或自动（邮箱一致等）合并流程，合并前需要验证双方所有权并记录审计，合并在事务中移动/合并 credentials、profile，并标记被合并 account 为 merged/soft-deleted。
- 注销/删除
  - 支持软删除并在后台 task 中清理或匿名化 PII。

四、字段与约束建议（细节）
- account
  - id (uuid), tenant_id (nullable), primary_email_id (fk to email or null), status (active/blocked/disabled), created_at, updated_at, deleted_at, last_login_at, flags/jsonb (可存租户/角色指针)
  - 唯一索引: tenant_id + id
- profile
  - account_id (fk), display_name, first_name, last_name, avatar_url, locale, timezone, metadata (jsonb)
- email (或 email_credentials)
  - id, account_id, email (lowercase), normalized_email, verified_at, verification_code_hash/expiry（如果需要），is_primary, created_at, updated_at, status
  - 唯一索引: tenant_id + email（仅对 verified=true 或 active 的记录强制唯一，或者应用逻辑防冲突）
- phone
  - id, account_id, phone_e164, verified_at, last_verified_at, is_primary, created_at, status
  - 索引: phone_e164
- oauth (第三方)
  - id, account_id, provider (google/facebook/github/...), provider_user_id, provider_display_name, linked_at, scopes (jsonb), token_encrypted (nullable), token_expires_at (nullable), refresh_token_encrypted (nullable), last_sync_at
  - 唯一索引: provider + provider_user_id
- password (可选)
  - id, account_id, password_hash, algorithm (bcrypt/argon2), salt (if used), created_at, updated_at, failed_attempts, locked_until
- credential_meta/identity (通用表，可替代上面多个)
  - id, account_id, kind, key, value(jsonb), verified_at, status
- audit
  - id, account_id (nullable), actor (who triggered), action, details (jsonb), created_at

五、示例 SQL 草案（Postgres 风格）
请根据你实际需求调整字段与类型。

```sql
-- accounts
CREATE TABLE account (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NULL,
  status varchar(16) NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz NULL,
  last_login_at timestamptz NULL,
  metadata jsonb NULL
);

-- profiles
CREATE TABLE profile (
  account_id uuid PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
  display_name varchar(255),
  first_name varchar(100),
  last_name varchar(100),
  locale varchar(16),
  timezone varchar(64),
  avatar_url text,
  data jsonb
);

-- email credentials
CREATE TABLE email_credential (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  tenant_id uuid NULL,
  email citext NOT NULL,
  normalized_email text GENERATED ALWAYS AS (lower(email)) STORED,
  is_primary boolean NOT NULL DEFAULT false,
  verified_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  status varchar(16) NOT NULL DEFAULT 'active'
);
CREATE UNIQUE INDEX ux_email_tenant ON email_credential(tenant_id, normalized_email) WHERE status='active' AND verified_at IS NOT NULL;

-- phone credentials
CREATE TABLE phone_credential (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  phone_e164 varchar(32) NOT NULL,
  is_primary boolean NOT NULL DEFAULT false,
  verified_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  status varchar(16) NOT NULL DEFAULT 'active'
);
CREATE UNIQUE INDEX ux_phone ON phone_credential(phone_e164) WHERE status='active' AND verified_at IS NOT NULL;

-- oauth providers
CREATE TABLE oauth_credential (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  provider varchar(64) NOT NULL,
  provider_user_id text NOT NULL,
  provider_display_name text,
  linked_at timestamptz NOT NULL DEFAULT now(),
  scopes jsonb NULL,
  token_encrypted text NULL,
  token_expires_at timestamptz NULL,
  refresh_token_encrypted text NULL,
  last_sync_at timestamptz NULL,
  status varchar(16) NOT NULL DEFAULT 'active'
);
CREATE UNIQUE INDEX ux_oauth_provider_user ON oauth_credential(provider, provider_user_id);

-- password credentials (if applicable)
CREATE TABLE password_credential (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  algorithm varchar(32) NOT NULL DEFAULT 'argon2',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  failed_attempts int NOT NULL DEFAULT 0,
  locked_until timestamptz NULL
);

-- audit
CREATE TABLE audit_event (
  id bigserial PRIMARY KEY,
  account_id uuid NULL,
  actor text NULL,
  action varchar(128) NOT NULL,
  details jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

六、安全与实现注意事项
- 密码：使用 Argon2id 或 bcrypt（推荐 Argon2）并保存参数；不要自己实现哈希算法。
- Token 存储：refresh token 若需要可撤销，建议将 refresh token 的哈希存储在 DB（像密码一样），实际 token 只返回给客户端。
- 第三方 token：如果必须长期保存，使用 KMS/Vault 加密字段，且设置到期/轮换策略。
- 验证码：不要把明文验证码存 DB，改存 hash+expiry；验证码发送次数控制，防暴力。
- 速率与反 abuse：对注册/发送验证码/登录尝试做速率限制与 IP/账户封禁策略。
- 事务性：注册/绑定/合并等说明文需要在事务中操作并记录 audit。
- 索引与查询优化：常用查询字段（email、phone、provider_user_id、account_id）要加索引；查询 email 用 normalized lower-case。
- 多租户：如果支持多租户，所有唯一索引都应包含 tenant_id 或在逻辑层限制。

七、示例：自动创建账号（邮箱验证码登录）流程（伪代码）
- 1) 用户提交邮箱 + 验证码
- 2) 验证码校验（hash比对 + expiry）
- 3) 查找 email_credential by normalized_email：
   - 如果存在且 verified_at 不为空 -> 返回对应 account 登录成功（更新 last_login_at）
   - 否则在事务中：
     - 创建 account
     - 创建 profile（可选）
     - 创建 email_credential (verified_at = now)
     - 记录 audit_event
- 4) 返回 session + refresh token（refresh token 存其 hash）

八、总结建议（要点回顾）
- 你的分表思路合理，推荐：
  - 在凭证表增加 verified/status/last_used 字段
  - 考虑通用 credential 表或保持现有多表但统一接口
  - 第三方 token 最小化存储或加密并短期保存
  - 实现软删除、审计、事务、索引与速率限制
  - 设计合并/绑定的幂等与冲突处理策略

如果你愿意，我可以：
- 基于上面的 SQL 生成对应的 Go 数据模型（struct）与 repository 接口（CRUD + 搜索方法），
- 或者直接为 internal/authn/domain 下生成具体文件（domain/entity、repo 接口、service 模板、task 清理脚本）。
告诉我你想先要哪一部分，我会给出具体代码草案。

---

将邮箱验证码、短信验证码、第三方 OAuth 等不同登录方式合并成一张通用 credential（或 identity）表是常见做法，能统一接口并降低代码重复，但也会带来一些冗余与复杂性。下面我给出实用建议：必须字段、可选/扩展字段、如何用 jsonb 存放 provider 特有数据、必要索引与唯一性策略、优劣比较、迁移与实现建议，以及示例 SQL/Go struct，帮助你做决定并落地。

一、通用 credential 表应包含的字段（最小、安全与可扩展）
- id (uuid) — 主键
- account_id (uuid, nullable) — 关联的 account（登录成功后绑定），创建时可能为空（临时凭证）
- kind (varchar) — 凭证类型，如 "email", "phone", "password", "oauth", "passkey"
- key (text) — 标识凭证的主键：email 地址（小写）、手机号（E.164）、provider_user_id（第三方的 user id）、credential id（passkey id）
- normalized_key (text) — 规范化后的 key（lowercase/email normalized），用于索引与搜索
- secret_hash (text, nullable) — 用于存储密码或 refresh token/hash（不可逆）；或验证码 hash；对长期敏感 token 使用加密存储或 KMS
- secret_enc (text, nullable) — 对需要可解密保留的 token（第三方 access_token）做 KMS 加密后存放（尽量避免）
- provider (varchar, nullable) — 第三方提供者名称，如 "google","github"（仅在 kind="oauth" 时有效）
- verified_at (timestamptz, nullable) — 何时验证（邮箱/手机号 被确认）
- status (varchar) — active/disabled/revoked/soft_deleted
- meta (jsonb, nullable) — provider-specific 或扩展字段（例如 oauth scopes、avatar、public_key 中的 attestation数据、验证码 expiry 等）
- created_at, updated_at, last_used_at, deleted_at
- tenant_id (uuid, nullable) — 多租户场景下的隔离字段
- is_primary (boolean) — 是否是 account 的主联系方式（可选）

二、为什么这些字段足够且必要
- kind + key 提供统一寻找凭证的方式（例如 SELECT ... WHERE kind='email' AND normalized_key=...）
- secret_hash 仅保存能够验证的 hash（密码或 refresh token 的哈希）；验证码同样只存哈希+expiry 放在 meta 中
- provider + meta 保持第三方特有信息，避免为每个 provider 建新列
- verified_at/status 用于决定是否可立即登录或必须先验证
- tenant_id 支持多租户唯一性约束

三、如何把 provider-specific 数据放进 meta（示例）
- email: meta = {"verification_code_exp": "...", "verification_sent_count": 1}
- phone: meta = {"last_sms_sent": "...", "sms_rate_limited": false}
- oauth: meta = {"scopes": ["email","profile"], "profile_name":"Alice", "avatar":"..."}
- passkey: meta = {"public_key":"...", "sign_count": 42}

四、必要索引与唯一性策略
- 索引:
  - (kind, normalized_key)
  - account_id
  - provider + key (或 provider + provider_user_id 存在于 key)
  - tenant_id + normalized_key（多租户）
- 唯一性:
  - 对于已验证且 active 的凭证通常需要逻辑唯一性（例如同一 tenant 下同一 email 只能被一个 active account 使用）。
  - 在 Postgres 中可用部分唯一索引：
    CREATE UNIQUE INDEX ux_credential_email_tenant ON credential(kind, normalized_key, tenant_id) WHERE kind='email' AND status='active' AND verified_at IS NOT NULL;
  - 对 oauth 可用 UNIQUE(provider, key)（provider_user_id 放在 key）

五、安全与敏感字段处理
- 永久性秘密（密码、refresh token）只存不可逆 hash（bcrypt/argon2 for password；HMAC/SHA256 hash for refresh token），不要存明文。
- 第三方 access_token 若必须保存，使用 KMS/Vault 加密并设置 TTL；在 DB 只存加密串与过期时间。
- 验证码只存 hash + expiry（meta 字段），并限制尝试次数与速率。
- 所有关键敏感字段访问需受最小权限控制与审计。

六、是否会产生冗余？冗余来自哪里，如何控制
- 冗余来源：
  - meta jsonb 会保存 provider 特定字段，很多行会有空的 meta 或有同名字段在不同 kind 中含义不同，导致稀疏列现象。
  - 对于高性能查询（比如只查手机号或只查 oauth），需要额外索引字段，导致表中有些列对某些 kind 无用。
- 控制方式：
  - 将 meta 用于非关键查询字段，关键字段（如 provider_user_id）可直接存放在 key 或额外列以便索引。
  - 使用部分索引和约束，避免在全表扫描时承担 cost。
  - 在读密集场景下，为某些 kind 建立物化视图或缓存（Redis）以提高查询性能。
- 总结：有少量冗余/稀疏列是可接受的换取统一模型与更小的代码量；但当某一类凭证的字段非常多或查询热点特别集中时，分表会更高效。

七、合并 vs 分表 的推荐（何时用哪种）
- 推荐合并（单表 credential）当：
  - 项目处于中小规模或团队愿意维护统一 credential 接口；
  - 你希望逻辑统一、repository 简化、代码复用（查找凭证、绑定、解绑、验证等统一实现）；
  - 不希望频繁新增凭证类型表；
- 推荐分表（email/phone/oauth/... 单独表）当：
  - 各凭证类型字段非常不同且复杂（例如 passkey 需要大量专用列或大二进制公钥），或需要独立优化查询/索引；
  - 超高并发场景，某类凭证的查询占绝大多数，且需要最小列扫描与专门索引；
  - 合规或审计要求对某类凭证独立策略（比如必须把 oauth token 存在独立审计流水，并加密单独管理）；
- 实际折中方案：
  - 采用通用 credential 作主表（大多数场景使用），对少数复杂/高性能类型（passkey、oauth token）再做“附表”或视图；即主表+可选细表的混合模型。

八、样例通用表 SQL（Postgres 风格，已包含部分索引与部分唯一约束）
```sql
CREATE TABLE credential (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NULL REFERENCES account(id) ON DELETE SET NULL,
  tenant_id uuid NULL,
  kind varchar(32) NOT NULL, -- email/phone/password/oauth/passkey
  key text NOT NULL,         -- email/phone/provider_user_id/passkey_id
  normalized_key text GENERATED ALWAYS AS (lower(key)) STORED,
  provider varchar(64) NULL, -- for oauth: google/github...
  secret_hash text NULL,     -- password hash or refresh token hash
  secret_enc text NULL,      -- encrypted tokens (KMS encrypted)
  verified_at timestamptz NULL,
  status varchar(16) NOT NULL DEFAULT 'active',
  is_primary boolean NOT NULL DEFAULT false,
  meta jsonb NULL,
  last_used_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz NULL
);

CREATE INDEX idx_credential_kind_key ON credential(kind, normalized_key);
CREATE INDEX idx_credential_account ON credential(account_id);
CREATE UNIQUE INDEX ux_credential_provider_key ON credential(provider, key) WHERE provider IS NOT NULL;

-- 部分唯一索引（同一 tenant 下已验证的 email 只能有一个 active 记录）
CREATE UNIQUE INDEX ux_credential_email_tenant ON credential(kind, normalized_key, tenant_id)
  WHERE kind='email' AND status='active' AND verified_at IS NOT NULL;
```

九、示例行（展示如何在一张表中表达不同类型）
- 邮箱（已验证）:
  {kind: "email", key: "alice@example.com", normalized_key: "alice@example.com", verified_at: "2025-10-23T..", meta: {"verification_method":"code"}}
- 手机（待验证）:
  {kind: "phone", key: "+8613800000000", meta: {"verification_code_hash":"sha256...", "expires_at":"..."}}
- 第三方 Google:
  {kind:"oauth", provider:"google", key:"google|1234567890", meta: {"scopes":["email","profile"], "profile_name":"Alice"}, secret_enc: "<kms encrypted token>"}

十、迁移与实施建议
- 如果当前已有分表设计，迁移到通用表可以逐步进行：
  1. 新写入先写入通用表（双写短期），老表继续读旧逻辑；
  2. 后台脚本把老表数据迁移到 credential 表并对比；
  3. 切换代码只读 credential 表，老表退役。
- 发行兼容 API：保持 repository 接口稳定，适配底层实现变更。
- 性能监控：上线后密切关注 credential 表的热点查询与索引压力，必要时为某类凭证拆分专表。

十一、Go struct 示例（供 repository 使用）
```go
type CredentialKind string
const (
  KindEmail CredentialKind = "email"
  KindPhone CredentialKind = "phone"
  KindOAuth CredentialKind = "oauth"
  KindPassword CredentialKind = "password"
)

type Credential struct {
  ID            uuid.UUID
  AccountID     *uuid.UUID
  TenantID      *uuid.UUID
  Kind          CredentialKind
  Key           string
  NormalizedKey string
  Provider      *string
  SecretHash    *string
  SecretEnc     *string
  VerifiedAt    *time.Time
  Status        string
  IsPrimary     bool
  Meta          map[string]interface{}
  LastUsedAt    *time.Time
  CreatedAt     time.Time
  UpdatedAt     time.Time
}
```

十二、结论与建议（简短）
- 若你项目规模中小、想要快速迭代并保持统一逻辑：使用通用 credential 表（推荐）。
- 若你预计某类凭证（如 passkey 或需要大量 provider token 管理）将变复杂或成为性能热点：采用主表 + 专属附表的混合策略，或直接分表。
- 无论选择哪种，关键在于：设计好索引、唯一性约束、敏感数据加密策略与审计路径，并在 service 层封装好 repository 接口以便未来切换实现。

如果你愿意，我可以：
- 基于你现有 DB（或你想用的 Postgres 版本）生成完整 CREATE TABLE 脚本与迁移脚本草案；
- 或生成 repository 接口（Go）与示例实现（Postgres）以配合你的 internal/authn/service。你想先要哪一项？

---