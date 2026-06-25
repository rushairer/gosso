-- 0019_webauthn_credential_flags.up.sql
-- Add flags column to webauthn_credentials to store authenticator flags
-- (BackupEligible, BackupState, etc.) from registration/login responses.
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS flags SMALLINT NOT NULL DEFAULT 0;
