package domain

import (
	"errors"
	"fmt"
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

// IsValidProvider reports whether p is a recognized identity provider.
func IsValidProvider(p Provider) bool {
	switch p {
	case ProviderGoogle, ProviderGitHub, ProviderWeChat:
		return true
	}
	return false
}

// NewFederatedIdentity creates a new federated identity.
// Returns an error if accountID or providerUserID is empty.
func NewFederatedIdentity(accountID string, provider Provider, providerUserID string, profile map[string]any) (*FederatedIdentity, error) {
	if accountID == "" {
		return nil, errors.New("account ID is required")
	}
	if provider == "" {
		return nil, errors.New("provider is required")
	}
	if !IsValidProvider(provider) {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
	if providerUserID == "" {
		return nil, errors.New("provider user ID is required")
	}
	if profile == nil {
		profile = make(map[string]any)
	}

	return &FederatedIdentity{
		ID:             uuid.New().String(),
		AccountID:      accountID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Profile:        profile,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}, nil
}

// IsDeleted reports whether the federated identity has been soft-deleted.
func (fi *FederatedIdentity) IsDeleted() bool {
	return fi.DeletedAt != nil
}

// SoftDelete soft-deletes the federated identity.
func (fi *FederatedIdentity) SoftDelete() error {
	if fi.IsDeleted() {
		return errors.New("federated identity is already deleted")
	}
	now := time.Now()
	fi.DeletedAt = &now
	fi.UpdatedAt = now
	return nil
}

// UpdateProfile updates the profile data.
func (fi *FederatedIdentity) UpdateProfile(profile map[string]any) {
	if profile == nil {
		profile = make(map[string]any)
	}
	fi.Profile = profile
	fi.UpdatedAt = time.Now()
}
