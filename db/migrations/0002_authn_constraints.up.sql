-- 0002_authn_constraints.sql
-- 创建部分唯一索引与额外约束（Postgres 专用）

-- 同一 tenant 下，已验证且 active 的 email 唯一
CREATE UNIQUE INDEX IF NOT EXISTS ux_credentials_email_tenant ON credentials(kind, normalized_key, tenant_id)
  WHERE kind='email' AND status='active' AND verified_at IS NOT NULL;

-- oauth provider + key 唯一
CREATE UNIQUE INDEX IF NOT EXISTS ux_credentials_provider_key ON credentials(provider, key) WHERE provider IS NOT NULL;

-- 保证每个 account 最多有一个 is_primary=true 的 credential
CREATE UNIQUE INDEX IF NOT EXISTS ux_account_primary_credential ON credentials(account_id) WHERE is_primary = true;

-- 如果需要 citext 支持 email case-insensitive（可选）
-- ALTER TABLE credentials ALTER COLUMN key TYPE citext USING key::citext; -- 仅在需要时启用
