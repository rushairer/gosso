package domain

import (
	"time"

	"github.com/google/uuid"
)

// AccountStatus 表示账号状态
type AccountStatus string

const (
	AccountStatusActive   AccountStatus = "active"   // 正常
	AccountStatusDisabled AccountStatus = "disabled" // 禁用
	AccountStatusBlocked  AccountStatus = "blocked"  // 封禁
	AccountStatusMerged   AccountStatus = "merged"   // 已合并（被合并到其他账号）
)

// Account 表示一个用户的身份主体（轻量）
// 说明：
// - 账号与凭证（Credential）分离存储，账号只包含识别与状态信息；
// - 详尽的用户可见信息存放在 Profile 表；
// - PrimaryCredentialID 用于快速定位主联系方式/主凭证（例如用于发送重置邮件或通知）。
// - Metadata 用于存放可扩展的业务字段（在 Postgres 中建议为 jsonb）。
type Account struct {
	ID                  uuid.UUID              `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`                        // 主键
	TenantID            *uuid.UUID             `json:"tenant_id,omitempty" gorm:"type:uuid;index:idx_account_tenant"`                   // 多租户 ID，可选
	PrimaryCredentialID *uuid.UUID             `json:"primary_credential_id,omitempty" gorm:"type:uuid;index:idx_account_primary_cred"` // 主凭证 FK（可为空）
	Status              AccountStatus          `json:"status" gorm:"type:varchar(32);index:idx_account_status"`                         // 账号状态
	CreatedAt           time.Time              `json:"created_at" gorm:"autoCreateTime"`                                                // 创建时间
	UpdatedAt           time.Time              `json:"updated_at" gorm:"autoUpdateTime"`                                                // 更新时间
	DeletedAt           *time.Time             `json:"deleted_at,omitempty" gorm:"index:idx_account_deleted"`                           // 软删除时间（可为空）
	LastLoginAt         *time.Time             `json:"last_login_at,omitempty" gorm:"index:idx_account_last_login"`                     // 最后登录时间
	Metadata            map[string]interface{} `json:"metadata,omitempty" gorm:"type:jsonb"`                                            // 可扩展元数据（jsonb）
}

// TableName 指定 GORM 使用的表名
func (Account) TableName() string {
	return "accounts"
}
