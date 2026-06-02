-- 0006_fix_constraints.up.sql
-- 补充缺失的外键约束和 updated_at 触发器

-- ================================================
-- 外键约束（0002 缺失）
-- ================================================

-- account_credentials → accounts
ALTER TABLE account_credentials
    ADD CONSTRAINT fk_account_credentials_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- federated_identities → accounts
ALTER TABLE federated_identities
    ADD CONSTRAINT fk_federated_identities_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- groups.parent_id → groups (自引用)
ALTER TABLE groups
    ADD CONSTRAINT fk_groups_parent
    FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE SET NULL;

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
