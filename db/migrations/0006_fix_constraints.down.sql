-- 0006_fix_constraints.down.sql
-- 回滚缺失的外键约束和 updated_at 触发器

-- 删除触发器
DROP TRIGGER IF EXISTS update_audit_entry_updated_at ON audit_entry;
DROP TRIGGER IF EXISTS update_oauth2_clients_updated_at ON oauth2_clients;

-- 删除外键约束
ALTER TABLE webauthn_credentials DROP CONSTRAINT IF EXISTS fk_webauthn_credentials_account;
ALTER TABLE account_groups DROP CONSTRAINT IF EXISTS fk_account_groups_group;
ALTER TABLE account_groups DROP CONSTRAINT IF EXISTS fk_account_groups_account;
ALTER TABLE account_roles DROP CONSTRAINT IF EXISTS fk_account_roles_role;
ALTER TABLE account_roles DROP CONSTRAINT IF EXISTS fk_account_roles_account;
ALTER TABLE groups DROP CONSTRAINT IF EXISTS fk_groups_parent;
ALTER TABLE federated_identities DROP CONSTRAINT IF EXISTS fk_federated_identities_account;
ALTER TABLE account_credentials DROP CONSTRAINT IF EXISTS fk_account_credentials_account;
