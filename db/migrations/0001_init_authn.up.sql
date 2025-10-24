-- 0001_init_authn.sql
-- 创建 accounts/profiles/credentials 及基础索引，针对 Postgres

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- accounts 表
CREATE TABLE IF NOT EXISTS accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NULL,
  primary_credential_id uuid NULL,
  status varchar(32) NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz NULL,
  last_login_at timestamptz NULL,
  metadata jsonb NULL
);
CREATE INDEX IF NOT EXISTS idx_account_tenant ON accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_account_primary_cred ON accounts(primary_credential_id);
CREATE INDEX IF NOT EXISTS idx_account_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_account_deleted ON accounts(deleted_at);
CREATE INDEX IF NOT EXISTS idx_account_last_login ON accounts(last_login_at);

-- profiles 表
CREATE TABLE IF NOT EXISTS profiles (
  account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  display_name varchar(255),
  first_name varchar(100),
  last_name varchar(100),
  locale varchar(16),
  timezone varchar(64),
  avatar_url text,
  data jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- credentials 表（通用凭证模型）
CREATE TABLE IF NOT EXISTS credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NULL REFERENCES accounts(id) ON DELETE SET NULL,
  tenant_id uuid NULL,
  kind varchar(32) NOT NULL,
  key text NOT NULL,
  normalized_key text GENERATED ALWAYS AS (lower(key)) STORED,
  provider varchar(64) NULL,
  secret_hash text NULL,
  secret_enc text NULL,
  verified_at timestamptz NULL,
  status varchar(32) NOT NULL DEFAULT 'active',
  is_primary boolean NOT NULL DEFAULT false,
  meta jsonb NULL,
  last_used_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_normkey ON credentials(normalized_key);
CREATE INDEX IF NOT EXISTS idx_credential_account ON credentials(account_id);
CREATE INDEX IF NOT EXISTS idx_credential_tenant ON credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credential_kind ON credentials(kind);
CREATE INDEX IF NOT EXISTS idx_credential_provider ON credentials(provider);
CREATE INDEX IF NOT EXISTS idx_credential_verified ON credentials(verified_at);
CREATE INDEX IF NOT EXISTS idx_credential_status ON credentials(status);
CREATE INDEX IF NOT EXISTS idx_credential_is_primary ON credentials(is_primary);
CREATE INDEX IF NOT EXISTS idx_credential_last_used ON credentials(last_used_at);
CREATE INDEX IF NOT EXISTS idx_credential_deleted ON credentials(deleted_at);

-- 注意：部分唯一索引在后续 migration 中创建（示例在 0002）
