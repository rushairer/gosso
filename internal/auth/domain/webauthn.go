package domain

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnCredential represents a stored WebAuthn passkey credential.
type WebAuthnCredential struct {
	ID              string
	AccountID       string
	CredentialID    []byte
	PublicKey       []byte
	SignCount       uint32
	AAGUID          []byte
	Transports      []string
	AttestationType string
	Name            string
	Verified        bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastUsedAt      *time.Time
	DeletedAt       *time.Time
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
