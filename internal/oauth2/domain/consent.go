package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrConsentNotFound is returned when a consent record does not exist.
var ErrConsentNotFound = errors.New("consent not found")

// Consent domain sentinel errors.
var (
	ErrConsentAccountIDRequired = errors.New("consent: account_id is required")
	ErrConsentClientIDRequired  = errors.New("consent: client_id is required")
)

// NewConsent creates a new Consent with the required fields.
// Validates that accountID and clientID are non-empty.
func NewConsent(accountID, clientID string, scopes []string) (*Consent, error) {
	if accountID == "" {
		return nil, ErrConsentAccountIDRequired
	}
	if clientID == "" {
		return nil, ErrConsentClientIDRequired
	}
	if scopes == nil {
		scopes = []string{}
	}
	return &Consent{
		ID:        uuid.New().String(),
		AccountID: accountID,
		ClientID:  clientID,
		Scopes:    scopes,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
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
