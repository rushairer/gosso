-- WebAuthn credentials table for passkey support
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid BYTEA,
    transports JSONB DEFAULT '[]',
    attestation_type VARCHAR(32) NOT NULL DEFAULT 'none',
    name VARCHAR(255) NOT NULL DEFAULT '',
    verified BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_account_id
    ON webauthn_credentials(account_id) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id
    ON webauthn_credentials(credential_id) WHERE deleted_at IS NULL;
