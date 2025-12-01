package domain

import (
	"time"

	"github.com/google/uuid"
)

// Provider 第三方身份提供商
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderGitHub Provider = "github"
	ProviderWeChat Provider = "wechat"
)

// FederatedIdentity 第三方身份领域模型
type FederatedIdentity struct {
	ID             string         `json:"id"`
	AccountID      string         `json:"account_id"`
	Provider       Provider       `json:"provider"`
	ProviderUserID string         `json:"provider_user_id"`
	Profile        map[string]any `json:"profile"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      *time.Time     `json:"deleted_at,omitempty"`
}

// NewFederatedIdentity 创建新的第三方身份
func NewFederatedIdentity(accountID string, provider Provider, providerUserID string, profile map[string]interface{}) *FederatedIdentity {
	if profile == nil {
		profile = make(map[string]interface{})
	}

	return &FederatedIdentity{
		ID:             uuid.New().String(),
		AccountID:      accountID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Profile:        profile,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

// IsDeleted 是否已软删除
func (fi *FederatedIdentity) IsDeleted() bool {
	return fi.DeletedAt != nil
}

// SoftDelete 软删除第三方身份
func (fi *FederatedIdentity) SoftDelete() {
	now := time.Now()
	fi.DeletedAt = &now
	fi.UpdatedAt = now
}

// UpdateProfile 更新资料
func (fi *FederatedIdentity) UpdateProfile(profile map[string]interface{}) {
	fi.Profile = profile
	fi.UpdatedAt = time.Now()
}
