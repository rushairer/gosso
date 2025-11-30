package domain

import (
	"time"

	"github.com/google/uuid"
)

// AccountStatus 账号状态
type AccountStatus string

const (
	AccountStatusActive    AccountStatus = "active"
	AccountStatusSuspended AccountStatus = "suspended"
	AccountStatusDeleted   AccountStatus = "deleted"
)

// Account 账号领域模型
type Account struct {
	ID          string                 `json:"id"`
	Username    *string                `json:"username,omitempty"`
	DisplayName string                 `json:"display_name"`
	AvatarURL   *string                `json:"avatar_url,omitempty"`
	Status      AccountStatus          `json:"status"`
	Locale      string                 `json:"locale"`
	Timezone    string                 `json:"timezone"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	DeletedAt   *time.Time             `json:"deleted_at,omitempty"`
}

// NewAccount 创建新账号
func NewAccount(displayName string) *Account {
	return &Account{
		ID:          uuid.New().String(),
		DisplayName: displayName,
		Status:      AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// IsDeleted 是否已软删除
func (a *Account) IsDeleted() bool {
	return a.DeletedAt != nil
}

// IsActive 是否为活跃状态
func (a *Account) IsActive() bool {
	return a.Status == AccountStatusActive && !a.IsDeleted()
}

// IsSuspended 是否已被禁用
func (a *Account) IsSuspended() bool {
	return a.Status == AccountStatusSuspended
}

// SoftDelete 软删除账号
func (a *Account) SoftDelete() {
	now := time.Now()
	a.DeletedAt = &now
	a.Status = AccountStatusDeleted
	a.UpdatedAt = now
}

// Suspend 禁用账号
func (a *Account) Suspend() {
	a.Status = AccountStatusSuspended
	a.UpdatedAt = time.Now()
}

// Activate 启用账号
func (a *Account) Activate() {
	a.Status = AccountStatusActive
	a.UpdatedAt = time.Now()
}
