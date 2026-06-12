-- 0016_webauthn_credentials_updated_at.down.sql
-- Remove updated_at column and trigger from webauthn_credentials table.

DROP TRIGGER IF EXISTS update_webauthn_credentials_updated_at ON webauthn_credentials;

ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS updated_at;
