-- 0010_drop_groups.up.sql
-- 删除未使用的 groups 和 account_groups 表（Go 代码中无任何使用）

-- 先删除外键约束（来自 0006）
ALTER TABLE account_groups DROP CONSTRAINT IF EXISTS fk_account_groups_group;
ALTER TABLE account_groups DROP CONSTRAINT IF EXISTS fk_account_groups_account;

-- 删除触发器
DROP TRIGGER IF EXISTS update_groups_updated_at ON groups;

-- 删除表
DROP TABLE IF EXISTS account_groups;
DROP TABLE IF EXISTS groups;
