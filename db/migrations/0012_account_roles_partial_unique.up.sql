-- 0012_account_roles_partial_unique.up.sql
-- Replace COALESCE-based unique index with a partial unique index
-- that correctly allows re-assigning roles after soft-delete.

DROP INDEX IF EXISTS idx_account_roles_unique;

CREATE UNIQUE INDEX idx_account_roles_unique
ON account_roles(account_id, role_id)
WHERE deleted_at IS NULL;
