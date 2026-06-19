package domain

import (
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// WebAuthnCredential domain sentinel errors.
var (
	ErrWebAuthnAccountIDRequired    = errors.New("webauthn: account_id is required")
	ErrWebAuthnCredentialIDRequired = errors.New("webauthn: credential_id is required")
	ErrWebAuthnPublicKeyRequired    = errors.New("webauthn: public_key is required")
	ErrWebAuthnAlreadyDeleted       = errors.New("webauthn: credential already deleted")
	ErrWebAuthnNameTooLong          = errors.New("webauthn: name exceeds maximum length")
)

const maxWebAuthnNameLength = 255 // Maximum credential name length

// WebAuthnCredential represents a stored WebAuthn passkey credential.
type WebAuthnCredential struct {
	ID              string     `json:"id"`
	AccountID       string     `json:"account_id"`
	CredentialID    []byte     `json:"credential_id,omitempty"`
	PublicKey       []byte     `json:"public_key,omitempty"`
	SignCount       uint32     `json:"sign_count"`
	AAGUID          []byte     `json:"aaguid,omitempty"`
	Transports      []string   `json:"transports,omitempty"`
	AttestationType string     `json:"attestation_type"`
	Name            string     `json:"name"`
	Verified        bool       `json:"verified"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty"`
}

// NewWebAuthnCredential creates a new WebAuthnCredential with validation.
func NewWebAuthnCredential(accountID string, credentialID, publicKey []byte, attestationType string, transports []string, signCount uint32, aagUID []byte, name string) (*WebAuthnCredential, error) {
	if accountID == "" {
		return nil, ErrWebAuthnAccountIDRequired
	}
	if len(credentialID) == 0 {
		return nil, ErrWebAuthnCredentialIDRequired
	}
	if len(publicKey) == 0 {
		return nil, ErrWebAuthnPublicKeyRequired
	}
	if len(name) > maxWebAuthnNameLength {
		return nil, ErrWebAuthnNameTooLong
	}
	now := time.Now()
	return &WebAuthnCredential{
		ID:              uuid.New().String(),
		AccountID:       accountID,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: attestationType,
		Transports:      transports,
		SignCount:       signCount,
		AAGUID:          aagUID,
		Name:            name,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// MarkUsed updates LastUsedAt to now.
func (c *WebAuthnCredential) MarkUsed() {
	now := time.Now()
	c.LastUsedAt = &now
}

// IncrementSignCount increments the sign counter (clone detection).
func (c *WebAuthnCredential) IncrementSignCount() {
	c.SignCount++
}

// IsDeleted returns true if the credential has been soft-deleted.
func (c *WebAuthnCredential) IsDeleted() bool {
	return c.DeletedAt != nil
}

// SoftDelete marks the credential as deleted. Returns ErrWebAuthnAlreadyDeleted if already deleted.
func (c *WebAuthnCredential) SoftDelete() error {
	if c.DeletedAt != nil {
		return ErrWebAuthnAlreadyDeleted
	}
	now := time.Now()
	c.DeletedAt = &now
	c.UpdatedAt = now
	return nil
}

// ToWebAuthnCredential converts to the go-webauthn library Credential type.
func (c *WebAuthnCredential) ToWebAuthnCredential() wa.Credential {
	return wa.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Authenticator: wa.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
		Transport: transportsToProtocol(c.Transports),
	}
}

// WebAuthnUser adapts account data to the webauthn.User interface.
type WebAuthnUser struct {
	accountID   string
	username    string
	displayName string
	credentials []wa.Credential
}

// NewWebAuthnUser creates a WebAuthnUser adapter.
func NewWebAuthnUser(accountID, username, displayName string, creds []WebAuthnCredential) *WebAuthnUser {
	waCreds := make([]wa.Credential, len(creds))
	for i, c := range creds {
		waCreds[i] = c.ToWebAuthnCredential()
	}
	return &WebAuthnUser{
		accountID:   accountID,
		username:    username,
		displayName: displayName,
		credentials: waCreds,
	}
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.accountID)
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *WebAuthnUser) WebAuthnCredentials() []wa.Credential {
	return u.credentials
}

func transportsToProtocol(transports []string) []protocol.AuthenticatorTransport {
	if len(transports) == 0 {
		return nil
	}
	result := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		result[i] = protocol.AuthenticatorTransport(t)
	}
	return result
}
