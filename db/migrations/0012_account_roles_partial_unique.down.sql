-- 0012_account_roles_partial_unique.down.sql
-- Restore the COALESCE-based unique index.

DROP INDEX IF EXISTS idx_account_roles_unique;

CREATE UNIQUE INDEX idx_account_roles_unique
ON account_roles(account_id, role_id, COALESCE(deleted_at, '1970-01-01'::timestamptz));
