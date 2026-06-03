-- Composite index for common query pattern: find credentials by account_id and type
-- Covers: WHERE account_id = $1 AND credential_type = $2 AND deleted_at IS NULL
CREATE INDEX idx_credentials_account_type
ON account_credentials(account_id, credential_type)
WHERE deleted_at IS NULL;
