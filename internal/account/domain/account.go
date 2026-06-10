package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AccountStatus represents the account lifecycle state.
type AccountStatus string

const (
	AccountStatusActive    AccountStatus = "active"
	AccountStatusSuspended AccountStatus = "suspended"
	AccountStatusDeleted   AccountStatus = "deleted"
)

// Account is the account domain model.
type Account struct {
	ID          string         `json:"id"`
	Username    *string        `json:"username,omitempty"`
	DisplayName string         `json:"display_name"`
	AvatarURL   *string        `json:"avatar_url,omitempty"`
	Status      AccountStatus  `json:"status"`
	Locale      string         `json:"locale"`
	Timezone    string         `json:"timezone"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   *time.Time     `json:"deleted_at,omitempty"`
}

// NewAccount creates a new account.
// Returns an error if displayName is empty or exceeds 255 characters.
func NewAccount(displayName string) (*Account, error) {
	if strings.TrimSpace(displayName) == "" {
		return nil, errors.New("display name is required")
	}
	if len(displayName) > 255 {
		return nil, errors.New("display name must not exceed 255 characters")
	}
	now := time.Now()
	return &Account{
		ID:          uuid.New().String(),
		DisplayName: displayName,
		Status:      AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    make(map[string]interface{}),
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// IsDeleted reports whether the account has been soft-deleted.
func (a *Account) IsDeleted() bool {
	return a.DeletedAt != nil
}

// IsActive reports whether the account is in active status.
func (a *Account) IsActive() bool {
	return a.Status == AccountStatusActive && !a.IsDeleted()
}

// IsSuspended reports whether the account has been suspended.
func (a *Account) IsSuspended() bool {
	return a.Status == AccountStatusSuspended && !a.IsDeleted()
}

// SoftDelete soft-deletes the account. Returns an error if already deleted.
func (a *Account) SoftDelete() error {
	if a.IsDeleted() {
		return errors.New("account is already deleted")
	}
	now := time.Now()
	a.DeletedAt = &now
	a.Status = AccountStatusDeleted
	a.UpdatedAt = now
	return nil
}

// Suspend suspends the account. Only active accounts can be suspended.
func (a *Account) Suspend() error {
	if a.IsDeleted() {
		return errors.New("cannot suspend a deleted account")
	}
	if a.Status != AccountStatusActive {
		return fmt.Errorf("cannot suspend account in %q status", a.Status)
	}
	a.Status = AccountStatusSuspended
	a.UpdatedAt = time.Now()
	return nil
}

// Activate reactivates the account. Only suspended accounts can be activated.
func (a *Account) Activate() error {
	if a.IsDeleted() {
		return errors.New("cannot activate a deleted account")
	}
	if a.Status != AccountStatusSuspended {
		return fmt.Errorf("cannot activate account in %q status", a.Status)
	}
	a.Status = AccountStatusActive
	a.UpdatedAt = time.Now()
	return nil
}
