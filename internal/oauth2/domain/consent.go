package domain

import (
	"errors"
	"time"
)

// ErrConsentNotFound is returned when a consent record does not exist.
var ErrConsentNotFound = errors.New("consent not found")

// Consent user authorization consent record for an OAuth2 client
type Consent struct {
	ID        string     `json:"id"`
	AccountID string     `json:"account_id"`
	ClientID  string     `json:"client_id"`
	Scopes    []string   `json:"scopes"`
	GrantedAt time.Time  `json:"granted_at"`
	CreatedAt time.Time  `json:"created_at,omitempty"`
	UpdatedAt time.Time  `json:"updated_at,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
