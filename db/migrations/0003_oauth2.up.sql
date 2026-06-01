-- 0003_oauth2.up.sql
-- OAuth2 客户端注册表
CREATE TABLE oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    client_id VARCHAR(255) NOT NULL,
    client_secret_hash TEXT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    grant_types JSONB NOT NULL DEFAULT '["authorization_code"]',
    scopes JSONB NOT NULL DEFAULT '["openid"]',
    is_confidential BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_oauth2_clients_client_id ON oauth2_clients(client_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_oauth2_clients_account_id ON oauth2_clients(account_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_oauth2_clients_deleted_at ON oauth2_clients(deleted_at) WHERE deleted_at IS NOT NULL;
