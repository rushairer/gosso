package domain

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func newTestWebAuthnCred() *WebAuthnCredential {
	return &WebAuthnCredential{
		ID:              "cred-001",
		AccountID:       "account-001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKey:       []byte("public-key-bytes"),
		SignCount:       5,
		AAGUID:          []byte("aaguid-bytes"),
		Transports:      []string{"internal", "hybrid"},
		AttestationType: "none",
		Name:            "My Passkey",
	}
}

// ──────────────────────────────────────────────
// MarkUsed
// ──────────────────────────────────────────────

func TestWebAuthnCredential_MarkUsed(t *testing.T) {
	c := newTestWebAuthnCred()
	assert.Nil(t, c.LastUsedAt)
	c.MarkUsed()
	assert.NotNil(t, c.LastUsedAt)
}

// ──────────────────────────────────────────────
// IncrementSignCount
// ──────────────────────────────────────────────

func TestWebAuthnCredential_IncrementSignCount(t *testing.T) {
	c := newTestWebAuthnCred()
	assert.Equal(t, uint32(5), c.SignCount)
	c.IncrementSignCount()
	assert.Equal(t, uint32(6), c.SignCount)
}

// ──────────────────────────────────────────────
// IsDeleted
// ──────────────────────────────────────────────

func TestWebAuthnCredential_IsDeleted_No(t *testing.T) {
	c := newTestWebAuthnCred()
	assert.False(t, c.IsDeleted())
}

func TestWebAuthnCredential_IsDeleted_Yes(t *testing.T) {
	c := newTestWebAuthnCred()
	now := time.Now()
	c.DeletedAt = &now
	assert.True(t, c.IsDeleted())
}

// ──────────────────────────────────────────────
// ToWebAuthnCredential
// ──────────────────────────────────────────────

func TestWebAuthnCredential_ToWebAuthnCredential(t *testing.T) {
	c := newTestWebAuthnCred()
	waCred := c.ToWebAuthnCredential()

	assert.Equal(t, []byte("cred-id-bytes"), waCred.ID)
	assert.Equal(t, []byte("public-key-bytes"), waCred.PublicKey)
	assert.Equal(t, "none", waCred.AttestationType)
	assert.Equal(t, []byte("aaguid-bytes"), waCred.Authenticator.AAGUID)
	assert.Equal(t, uint32(5), waCred.Authenticator.SignCount)
	assert.Len(t, waCred.Transport, 2)
	assert.Equal(t, protocol.AuthenticatorTransport("internal"), waCred.Transport[0])
	assert.Equal(t, protocol.AuthenticatorTransport("hybrid"), waCred.Transport[1])
}

func TestWebAuthnCredential_ToWebAuthnCredential_EmptyTransports(t *testing.T) {
	c := newTestWebAuthnCred()
	c.Transports = []string{}
	waCred := c.ToWebAuthnCredential()
	assert.Nil(t, waCred.Transport)
}

// ──────────────────────────────────────────────
// WebAuthnUser
// ──────────────────────────────────────────────

func TestNewWebAuthnUser(t *testing.T) {
	creds := []WebAuthnCredential{*newTestWebAuthnCred()}
	user := NewWebAuthnUser("account-001", "testuser", "Test User", creds)

	assert.Equal(t, []byte("account-001"), user.WebAuthnID())
	assert.Equal(t, "testuser", user.WebAuthnName())
	assert.Equal(t, "Test User", user.WebAuthnDisplayName())
	assert.Len(t, user.WebAuthnCredentials(), 1)
}

func TestNewWebAuthnUser_EmptyCredentials(t *testing.T) {
	user := NewWebAuthnUser("account-001", "testuser", "Test User", []WebAuthnCredential{})
	assert.Empty(t, user.WebAuthnCredentials())
}

// ──────────────────────────────────────────────
// WebAuthnUser satisfies wa.User interface
// ──────────────────────────────────────────────

func TestWebAuthnUser_ImplementsInterface(t *testing.T) {
	user := NewWebAuthnUser("id", "name", "display", nil)
	var _ wa.User = user
}
