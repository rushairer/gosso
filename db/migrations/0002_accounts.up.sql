-- 账号核心表
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50),
    display_name VARCHAR(100),
    avatar_url TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    locale VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 索引
CREATE UNIQUE INDEX idx_accounts_username ON accounts(username) WHERE username IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_accounts_status ON accounts(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_accounts_deleted_at ON accounts(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_accounts_created_at ON accounts(created_at DESC);

-- 注释
COMMENT ON TABLE accounts IS '账号主表';
COMMENT ON COLUMN accounts.id IS '账号唯一标识';
COMMENT ON COLUMN accounts.username IS '用户名（可选，唯一）';
COMMENT ON COLUMN accounts.display_name IS '显示名称';
COMMENT ON COLUMN accounts.status IS '状态：active/suspended/deleted';
COMMENT ON COLUMN accounts.deleted_at IS '软删除时间（NULL=未删除）';

-- ================================================
-- 认证凭证表
-- ================================================
CREATE TABLE IF NOT EXISTS account_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    credential_type VARCHAR(20) NOT NULL,
    identifier VARCHAR(255),
    credential_value TEXT,
    verified BOOLEAN DEFAULT false,
    primary_credential BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

-- 索引
CREATE UNIQUE INDEX idx_credentials_type_identifier 
ON account_credentials(credential_type, identifier) 
WHERE deleted_at IS NULL AND identifier IS NOT NULL;

CREATE INDEX idx_credentials_account_id 
ON account_credentials(account_id) 
WHERE deleted_at IS NULL;

CREATE INDEX idx_credentials_type_verified 
ON account_credentials(credential_type, verified) 
WHERE deleted_at IS NULL;

CREATE INDEX idx_credentials_deleted_at 
ON account_credentials(deleted_at) 
WHERE deleted_at IS NOT NULL;

-- 注释
COMMENT ON TABLE account_credentials IS '认证凭证表';
COMMENT ON COLUMN account_credentials.credential_type IS '凭证类型：password/email/phone/totp/webauthn/backup_code';
COMMENT ON COLUMN account_credentials.identifier IS '凭证标识符（邮箱/手机号等）';
COMMENT ON COLUMN account_credentials.credential_value IS '凭证值（密码 hash/TOTP secret/备用码 hash）';
COMMENT ON COLUMN account_credentials.verified IS '是否已验证';
COMMENT ON COLUMN account_credentials.primary_credential IS '是否为主要凭证';

-- ================================================
-- 第三方身份关联表
-- ================================================
CREATE TABLE IF NOT EXISTS federated_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    profile JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 索引
CREATE UNIQUE INDEX idx_federated_provider_user 
ON federated_identities(provider, provider_user_id) 
WHERE deleted_at IS NULL;

CREATE INDEX idx_federated_account_id 
ON federated_identities(account_id) 
WHERE deleted_at IS NULL;

-- 注释
COMMENT ON TABLE federated_identities IS '第三方身份关联表';
COMMENT ON COLUMN federated_identities.provider IS '身份提供商：google/github/wechat等';
COMMENT ON COLUMN federated_identities.provider_user_id IS '提供商用户 ID';
COMMENT ON COLUMN federated_identities.profile IS '用户资料（JSON）';

-- ================================================
-- 群组表（支持树形结构）
-- ================================================
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

-- 索引
CREATE UNIQUE INDEX idx_groups_name 
ON groups(name) 
WHERE deleted_at IS NULL;

CREATE INDEX idx_groups_parent_id 
ON groups(parent_id) 
WHERE deleted_at IS NULL;

-- 注释
COMMENT ON TABLE groups IS '群组表（支持树形结构）';
COMMENT ON COLUMN groups.parent_id IS '父群组 ID（NULL=顶级群组）';

-- ================================================
-- 角色表
-- ================================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 索引
CREATE UNIQUE INDEX idx_roles_name 
ON roles(name) 
WHERE deleted_at IS NULL;

-- 注释
COMMENT ON TABLE roles IS '角色表';
COMMENT ON COLUMN roles.permissions IS '权限列表（JSON 数组）';

-- ================================================
-- 账号-角色关联表
-- ================================================
CREATE TABLE IF NOT EXISTS account_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    role_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 索引
CREATE UNIQUE INDEX idx_account_roles_unique 
ON account_roles(account_id, role_id, COALESCE(deleted_at, '1970-01-01'::timestamptz));

CREATE INDEX idx_account_roles_account 
ON account_roles(account_id) 
WHERE deleted_at IS NULL;

CREATE INDEX idx_account_roles_role 
ON account_roles(role_id) 
WHERE deleted_at IS NULL;

-- 注释
COMMENT ON TABLE account_roles IS '账号-角色关联表';

-- ================================================
-- 账号-群组关联表
-- ================================================
CREATE TABLE IF NOT EXISTS account_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    group_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 索引
CREATE UNIQUE INDEX idx_account_groups_unique 
ON account_groups(account_id, group_id, COALESCE(deleted_at, '1970-01-01'::timestamptz));

CREATE INDEX idx_account_groups_account 
ON account_groups(account_id) 
WHERE deleted_at IS NULL;

CREATE INDEX idx_account_groups_group 
ON account_groups(group_id) 
WHERE deleted_at IS NULL;

-- 注释
COMMENT ON TABLE account_groups IS '账号-群组关联表';

-- ================================================
-- 触发器：自动更新 updated_at
-- ================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_accounts_updated_at BEFORE UPDATE ON accounts
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_federated_identities_updated_at BEFORE UPDATE ON federated_identities
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_groups_updated_at BEFORE UPDATE ON groups
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
