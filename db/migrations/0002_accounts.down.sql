-- 删除触发器
DROP TRIGGER IF EXISTS update_accounts_updated_at ON accounts;
DROP TRIGGER IF EXISTS update_federated_identities_updated_at ON federated_identities;
DROP TRIGGER IF EXISTS update_groups_updated_at ON groups;
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;

-- 删除触发器函数
DROP FUNCTION IF EXISTS update_updated_at_column();

-- 删除表（注意顺序：先删除关联表，再删除主表）
DROP TABLE IF EXISTS account_groups;
DROP TABLE IF EXISTS account_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS federated_identities;
DROP TABLE IF EXISTS account_credentials;
DROP TABLE IF EXISTS accounts;
