-- 0006_fix_constraints.up.sql
-- 补充缺失的外键约束和 updated_at 触发器

-- ================================================
-- 外键约束（0002 缺失）
-- ================================================

-- 清理孤儿数据：删除 account_credentials 中引用不存在的 account 的记录
DELETE FROM account_credentials ac
WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = ac.account_id);

-- account_credentials → accounts
ALTER TABLE account_credentials
    ADD CONSTRAINT fk_account_credentials_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- 清理孤儿数据：删除 federated_identities 中引用不存在的 account 的记录
DELETE FROM federated_identities fi
WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = fi.account_id);

-- federated_identities → accounts
ALTER TABLE federated_identities
    ADD CONSTRAINT fk_federated_identities_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- groups.parent_id → groups (自引用)
ALTER TABLE groups
    ADD CONSTRAINT fk_groups_parent
    FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE SET NULL;

-- 清理孤儿数据：删除 account_roles 中引用不存在的 account 或 role 的记录
DELETE FROM account_roles ar
WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = ar.account_id)
   OR NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = ar.role_id);

-- account_roles → accounts
ALTER TABLE account_roles
    ADD CONSTRAINT fk_account_roles_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- account_roles → roles
ALTER TABLE account_roles
    ADD CONSTRAINT fk_account_roles_role
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

-- account_groups → accounts
ALTER TABLE account_groups
    ADD CONSTRAINT fk_account_groups_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- account_groups → groups
ALTER TABLE account_groups
    ADD CONSTRAINT fk_account_groups_group
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE;

-- ================================================
-- 外键约束（0005 缺失）
-- ================================================

-- 清理孤儿数据：删除 webauthn_credentials 中引用不存在的 account 的记录
DELETE FROM webauthn_credentials wc
WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = wc.account_id);

-- webauthn_credentials → accounts
ALTER TABLE webauthn_credentials
    ADD CONSTRAINT fk_webauthn_credentials_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- ================================================
-- updated_at 触发器
-- ================================================

-- audit_entry（0001 缺失）
CREATE TRIGGER update_audit_entry_updated_at BEFORE UPDATE ON audit_entry
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- oauth2_clients（0003 缺失）
CREATE TRIGGER update_oauth2_clients_updated_at BEFORE UPDATE ON oauth2_clients
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ================================================
-- audit_record 补充索引：dd 列用于按日分区查询
-- ================================================
CREATE INDEX IF NOT EXISTS idx_audit_record_dd ON audit_record(dd);
