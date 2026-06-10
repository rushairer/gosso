-- 0014_oauth2_consents_soft_delete.down.sql
-- Remove soft-delete support from oauth2_consents table.

DROP INDEX IF EXISTS idx_oauth2_consents_account_client;
CREATE UNIQUE INDEX idx_oauth2_consents_account_client
ON oauth2_consents(account_id, client_id);

ALTER TABLE oauth2_consents DROP COLUMN IF EXISTS deleted_at;
