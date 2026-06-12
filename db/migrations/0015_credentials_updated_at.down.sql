-- 0015_credentials_updated_at.down.sql
-- Remove updated_at column and trigger from account_credentials table.

DROP TRIGGER IF EXISTS update_account_credentials_updated_at ON account_credentials;

ALTER TABLE account_credentials DROP COLUMN IF EXISTS updated_at;
