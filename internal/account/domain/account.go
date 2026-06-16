package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Account domain sentinel errors.
var (
	ErrDisplayNameRequired   = errors.New("display name is required")
	ErrDisplayNameTooLong    = errors.New("display name must not exceed 255 characters")
	ErrUsernameTooLong       = errors.New("username must not exceed 64 characters")
	ErrLocaleRequired        = errors.New("locale is required")
	ErrLocaleTooLong         = errors.New("locale must not exceed 10 characters")
	ErrTimezoneRequired      = errors.New("timezone is required")
	ErrAccountAlreadyDeleted = errors.New("account is already deleted")
	ErrCannotSuspendDeleted  = errors.New("cannot suspend a deleted account")
	ErrCannotActivateDeleted = errors.New("cannot activate a deleted account")
	ErrInvalidAccountStatus  = errors.New("invalid account status for this operation")
)

// AccountStatus represents the account lifecycle state.
type AccountStatus string

const (
	AccountStatusActive    AccountStatus = "active"
	AccountStatusSuspended AccountStatus = "suspended"
	AccountStatusDeleted   AccountStatus = "deleted"
)

// IsValidAccountStatus reports whether s is a known account status.
func IsValidAccountStatus(s AccountStatus) bool {
	switch s {
	case AccountStatusActive, AccountStatusSuspended, AccountStatusDeleted:
		return true
	}
	return false
}

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
//
// NOTE: time.Now() is used directly for domain-level timestamps (CreatedAt, UpdatedAt).
// Full clock injection (e.g. accepting a Clock interface) was considered but deemed
// over-engineering for this project; the domain timestamps are not critical-path for
// testability at this stage. If deterministic timestamps become needed (e.g. for
// snapshot testing or reproducible time-based logic), introduce a Clock parameter here.
func NewAccount(displayName string) (*Account, error) {
	now := time.Now()
	a := &Account{
		ID:          uuid.New().String(),
		DisplayName: displayName,
		Status:      AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    make(map[string]any),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	a.Sanitize()
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// Sanitize trims whitespace from account string fields.
// Must be called before Validate when accepting user input.
func (a *Account) Sanitize() {
	a.DisplayName = strings.TrimSpace(a.DisplayName)
	a.Locale = strings.TrimSpace(a.Locale)
	a.Timezone = strings.TrimSpace(a.Timezone)
}

// Validate checks if the account fields are correct.
// Call Sanitize() before Validate() when accepting user input.
func (a *Account) Validate() error {
	if a.DisplayName == "" {
		return ErrDisplayNameRequired
	}
	if len(a.DisplayName) > 255 {
		return ErrDisplayNameTooLong
	}
	if a.Username != nil && len(*a.Username) > 64 {
		return ErrUsernameTooLong
	}
	if !IsValidAccountStatus(a.Status) {
		return ErrInvalidAccountStatus
	}
	if a.Locale == "" {
		return ErrLocaleRequired
	}
	if len(a.Locale) > 10 {
		return ErrLocaleTooLong
	}
	if a.Timezone == "" {
		return ErrTimezoneRequired
	}
	return nil
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
		return ErrAccountAlreadyDeleted
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
		return ErrCannotSuspendDeleted
	}
	if a.Status != AccountStatusActive {
		return fmt.Errorf("%w: current status %q", ErrInvalidAccountStatus, a.Status)
	}
	a.Status = AccountStatusSuspended
	a.UpdatedAt = time.Now()
	return nil
}

// Activate reactivates the account. Only suspended accounts can be activated.
func (a *Account) Activate() error {
	if a.IsDeleted() {
		return ErrCannotActivateDeleted
	}
	if a.Status != AccountStatusSuspended {
		return fmt.Errorf("%w: current status %q", ErrInvalidAccountStatus, a.Status)
	}
	a.Status = AccountStatusActive
	a.UpdatedAt = time.Now()
	return nil
}
