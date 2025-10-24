package domain

import (
	"time"

	"github.com/google/uuid"
)

// CredentialKind 表示凭证类型
type CredentialKind string

const (
	CredentialKindEmail    CredentialKind = "email"    // 电子邮件
	CredentialKindPhone    CredentialKind = "phone"    // 手机号码（E.164）
	CredentialKindOAuth    CredentialKind = "oauth"    // 第三方 OAuth/OIDC
	CredentialKindPassword CredentialKind = "password" // 本地密码（hash 存储）
)

// Credential 为统一的凭证表结构，用于表示不同类型的登录/标识方式。
// 设计要点：
// - 使用 kind + key/normalized_key 唯一定位凭证（例如 email/phone/provider_user_id）；
// - secret_hash 用于保存不可逆的验证字符串（例如密码 hash、refresh token 的 hash）；
// - secret_enc 可用于保存需要解密的 token（需与 KMS/加密机制配合，尽量避免长期保存）；
// - meta 字段（jsonb）保存 provider 特有或扩展信息（如 oauth scopes、avatar 等）；
// - 对于 Postgres 的部分唯一约束（例如已验证邮箱在同一 tenant 内唯一），需通过 migration 创建部分唯一索引。
//
// 注意：GORM 的 struct tag 无法表达部分索引，下面注释中提供了建议的 SQL。
type Credential struct {
	ID            uuid.UUID              `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`                 // 主键
	AccountID     *uuid.UUID             `json:"account_id,omitempty" gorm:"type:uuid;index:idx_credential_account"`       // 关联的 account（登录成功后绑定）
	TenantID      *uuid.UUID             `json:"tenant_id,omitempty" gorm:"type:uuid;index:idx_credential_tenant"`         // 多租户 ID，可选
	Kind          CredentialKind         `json:"kind" gorm:"type:varchar(32);index:idx_credential_kind"`                   // 凭证类型
	Key           string                 `json:"key" gorm:"type:text;not null"`                                            // 原始 key（email/phone/provider_user_id 等）
	NormalizedKey string                 `json:"normalized_key" gorm:"type:text;index:idx_credential_normkey"`             // 归一化后的 key（例如小写 email）
	Provider      *string                `json:"provider,omitempty" gorm:"type:varchar(64);index:idx_credential_provider"` // 第三方提供者
	SecretHash    *string                `json:"secret_hash,omitempty" gorm:"type:text"`                                   // 不可逆哈希（密码、refresh token hash）
	SecretEnc     *string                `json:"secret_enc,omitempty" gorm:"type:text"`                                    // 加密存储的敏感字符串（需 KMS 解密）
	VerifiedAt    *time.Time             `json:"verified_at,omitempty" gorm:"index:idx_credential_verified"`               // 验证时间（邮箱/手机等）
	Status        string                 `json:"status" gorm:"type:varchar(32);index:idx_credential_status"`               // 状态：active/disabled/revoked
	IsPrimary     bool                   `json:"is_primary" gorm:"type:boolean;index:idx_credential_is_primary"`           // 是否为该 account 的主凭证
	Meta          map[string]interface{} `json:"meta,omitempty" gorm:"type:jsonb"`                                         // provider/方式特有扩展字段
	LastUsedAt    *time.Time             `json:"last_used_at,omitempty" gorm:"index:idx_credential_last_used"`             // 最近使用时间
	CreatedAt     time.Time              `json:"created_at" gorm:"autoCreateTime"`                                         // 创建时间
	UpdatedAt     time.Time              `json:"updated_at" gorm:"autoUpdateTime"`                                         // 更新时间
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" gorm:"index:idx_credential_deleted"`                 // 软删除时间
}

// TableName 指定 GORM 使用的表名
func (Credential) TableName() string {
	return "credentials"
}

// 建议在 migration 中创建如下部分唯一索引（示例）：
//
// -- 同一 tenant 下已验证且激活的 email 唯一
// CREATE UNIQUE INDEX ux_credentials_email_tenant ON credentials(kind, normalized_key, tenant_id)
//   WHERE kind='email' AND status='active' AND verified_at IS NOT NULL;
//
// -- oauth provider + key 唯一
// CREATE UNIQUE INDEX ux_credentials_provider_key ON credentials(provider, key) WHERE provider IS NOT NULL;
