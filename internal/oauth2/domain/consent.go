package domain

import (
	"errors"
	"fmt"
	"time"
)

// ErrConsentNotFound is returned when a consent record does not exist.
var ErrConsentNotFound = errors.New("consent not found")

// NewConsent creates a new Consent with the required fields.
// Validates that accountID and clientID are non-empty.
func NewConsent(accountID, clientID string, scopes []string) (*Consent, error) {
	if accountID == "" {
		return nil, fmt.Errorf("consent: account_id is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("consent: client_id is required")
	}
	if scopes == nil {
		scopes = []string{}
	}
	return &Consent{
		AccountID: accountID,
		ClientID:  clientID,
		Scopes:    scopes,
	}, nil
}

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
