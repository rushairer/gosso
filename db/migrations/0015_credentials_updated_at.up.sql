-- 0015_credentials_updated_at.up.sql
-- Add updated_at column and auto-update trigger to account_credentials table.
-- This aligns account_credentials with accounts, federated_identities, groups, and roles.

ALTER TABLE account_credentials ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TRIGGER update_account_credentials_updated_at BEFORE UPDATE ON account_credentials
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
