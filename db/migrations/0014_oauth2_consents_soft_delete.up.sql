-- 0014_oauth2_consents_soft_delete.up.sql
-- Add soft-delete support to oauth2_consents table.

ALTER TABLE oauth2_consents ADD COLUMN deleted_at TIMESTAMPTZ;

-- Replace the unique index with a partial unique index that excludes soft-deleted records.
-- This allows re-consent after revocation: the old soft-deleted row doesn't block a new insert.
DROP INDEX IF EXISTS idx_oauth2_consents_account_client;
CREATE UNIQUE INDEX idx_oauth2_consents_account_client
ON oauth2_consents(account_id, client_id)
WHERE deleted_at IS NULL;
