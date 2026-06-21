package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// ──────────────────────────────────────────────
// NewWebAuthnCredential
// ──────────────────────────────────────────────

func TestNewWebAuthnCredential_Success(t *testing.T) {
	cred, err := NewWebAuthnCredential(NewWebAuthnCredentialParams{
		AccountID:       "account-001",
		CredentialID:    []byte("cred-id"),
		PublicKey:       []byte("public-key"),
		AttestationType: "none",
		Transports:      []string{"internal"},
		SignCount:       0,
		AAGUID:          []byte("aaguid"),
		Name:            "My Passkey",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, cred.ID)
	assert.Equal(t, "account-001", cred.AccountID)
	assert.Equal(t, []byte("cred-id"), cred.CredentialID)
	assert.Equal(t, []byte("public-key"), cred.PublicKey)
	assert.Equal(t, "none", cred.AttestationType)
	assert.False(t, cred.CreatedAt.IsZero())
	assert.False(t, cred.UpdatedAt.IsZero())
}

func TestNewWebAuthnCredential_EmptyAccountID(t *testing.T) {
	_, err := NewWebAuthnCredential(NewWebAuthnCredentialParams{
		CredentialID: []byte("cred-id"),
		PublicKey:    []byte("pk"),
		Name:         "name",
	})
	assert.ErrorIs(t, err, ErrWebAuthnAccountIDRequired)
}

func TestNewWebAuthnCredential_EmptyCredentialID(t *testing.T) {
	_, err := NewWebAuthnCredential(NewWebAuthnCredentialParams{
		AccountID: "account-001",
		PublicKey: []byte("pk"),
		Name:      "name",
	})
	assert.ErrorIs(t, err, ErrWebAuthnCredentialIDRequired)
}

func TestNewWebAuthnCredential_EmptyPublicKey(t *testing.T) {
	_, err := NewWebAuthnCredential(NewWebAuthnCredentialParams{
		AccountID:    "account-001",
		CredentialID: []byte("cred-id"),
		Name:         "name",
	})
	assert.ErrorIs(t, err, ErrWebAuthnPublicKeyRequired)
}

// ──────────────────────────────────────────────
// SoftDelete
// ──────────────────────────────────────────────

func TestWebAuthnCredential_SoftDelete_Success(t *testing.T) {
	c := newTestWebAuthnCred()
	err := c.SoftDelete()
	assert.NoError(t, err)
	assert.True(t, c.IsDeleted())
	assert.False(t, c.DeletedAt.IsZero())
	assert.False(t, c.UpdatedAt.IsZero())
}

func TestWebAuthnCredential_SoftDelete_AlreadyDeleted(t *testing.T) {
	c := newTestWebAuthnCred()
	err := c.SoftDelete()
	require.NoError(t, err)
	err = c.SoftDelete()
	assert.True(t, errors.Is(err, ErrWebAuthnAlreadyDeleted))
}
