-- 0013_oauth2_consents.up.sql
-- Create oauth2_consents table for persistent consent storage.
-- Redis remains as a write-through cache; this table is the source of truth.

CREATE TABLE IF NOT EXISTS oauth2_consents (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    client_id  UUID NOT NULL,
    scopes     JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_oauth2_consents_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth2_consents_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_oauth2_consents_account_client
ON oauth2_consents(account_id, client_id);

CREATE TRIGGER update_oauth2_consents_updated_at BEFORE UPDATE ON oauth2_consents
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
