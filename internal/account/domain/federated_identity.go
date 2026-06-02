package domain

import (
	"time"

	"github.com/google/uuid"
)

// Provider represents a third-party identity provider.
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderGitHub Provider = "github"
	ProviderWeChat Provider = "wechat"
)

// FederatedIdentity is the federated identity domain model.
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

// NewFederatedIdentity creates a new federated identity.
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

// IsDeleted reports whether the federated identity has been soft-deleted.
func (fi *FederatedIdentity) IsDeleted() bool {
	return fi.DeletedAt != nil
}

// SoftDelete soft-deletes the federated identity.
func (fi *FederatedIdentity) SoftDelete() {
	now := time.Now()
	fi.DeletedAt = &now
	fi.UpdatedAt = now
}

// UpdateProfile updates the profile data.
func (fi *FederatedIdentity) UpdateProfile(profile map[string]interface{}) {
	fi.Profile = profile
	fi.UpdatedAt = time.Now()
}
