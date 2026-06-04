-- 0010_drop_groups.down.sql
-- 恢复 groups 和 account_groups 表（匹配 0002 + 0006）

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    parent_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_groups_name ON groups(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_groups_parent_id ON groups(parent_id) WHERE deleted_at IS NULL;

ALTER TABLE groups ADD CONSTRAINT fk_groups_parent
    FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE SET NULL;

CREATE TRIGGER update_groups_updated_at BEFORE UPDATE ON groups
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS account_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    group_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_account_groups_unique
    ON account_groups(account_id, group_id, COALESCE(deleted_at, '1970-01-01'::timestamptz));
CREATE INDEX idx_account_groups_account ON account_groups(account_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_account_groups_group ON account_groups(group_id) WHERE deleted_at IS NULL;

ALTER TABLE account_groups ADD CONSTRAINT fk_account_groups_account
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
ALTER TABLE account_groups ADD CONSTRAINT fk_account_groups_group
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE;
