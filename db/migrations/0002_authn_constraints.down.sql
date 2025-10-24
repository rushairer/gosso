-- 0002_authn_constraints.down.sql
-- 回滚认证系统的约束和唯一索引

-- 删除唯一索引
DROP INDEX IF EXISTS ux_account_primary_credential;
DROP INDEX IF EXISTS ux_credentials_provider_key;
DROP INDEX IF EXISTS ux_credentials_email_tenant;