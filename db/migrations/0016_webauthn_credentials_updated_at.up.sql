-- 0016_webauthn_credentials_updated_at.up.sql
-- Add updated_at column and auto-update trigger to webauthn_credentials table.
-- This aligns webauthn_credentials with account_credentials, accounts, federated_identities, and roles.

ALTER TABLE webauthn_credentials ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TRIGGER update_webauthn_credentials_updated_at BEFORE UPDATE ON webauthn_credentials
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
