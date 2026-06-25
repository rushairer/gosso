-- 0019_webauthn_credential_flags.down.sql
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS flags;
