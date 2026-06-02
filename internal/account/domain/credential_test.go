package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// NewPasswordCredential
// ──────────────────────────────────────────────

func TestNewPasswordCredential_Success(t *testing.T) {
	cred, err := NewPasswordCredential("account-001", "strong-password-123")
	require.NoError(t, err)
	assert.NotEmpty(t, cred.ID)
	assert.Equal(t, "account-001", cred.AccountID)
	assert.Equal(t, CredentialTypePassword, cred.Type)
	assert.NotEmpty(t, cred.Value)
	assert.True(t, cred.Verified)
	assert.NotEqual(t, "strong-password-123", cred.Value) // hashed, not plain
}

// ──────────────────────────────────────────────
// VerifyPassword
// ──────────────────────────────────────────────

func TestVerifyPassword_CorrectPassword(t *testing.T) {
	cred, err := NewPasswordCredential("account-001", "correct-password")
	require.NoError(t, err)
	assert.True(t, cred.VerifyPassword("correct-password"))
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	cred, err := NewPasswordCredential("account-001", "correct-password")
	require.NoError(t, err)
	assert.False(t, cred.VerifyPassword("wrong-password"))
}

func TestVerifyPassword_NonPasswordType(t *testing.T) {
	email := "test@example.com"
	cred := &Credential{
		Type:       CredentialTypeEmail,
		Identifier: &email,
		Value:      "some-value",
	}
	assert.False(t, cred.VerifyPassword("some-value"))
}

// ──────────────────────────────────────────────
// HashPassword
// ──────────────────────────────────────────────

func TestHashPassword_Deterministic(t *testing.T) {
	h1, err := HashPassword("test")
	require.NoError(t, err)
	assert.NotEmpty(t, h1)
	// Verify the hash works
	assert.NoError(t, compareHashAndPassword(h1, "test"))
}

func TestHashPassword_DifferentInputs(t *testing.T) {
	h1, _ := HashPassword("password1")
	h2, _ := HashPassword("password2")
	assert.NotEqual(t, h1, h2)
}

// compareHashAndPassword is a test helper
func compareHashAndPassword(hashed, password string) error {
	cred := &Credential{Type: CredentialTypePassword, Value: hashed}
	if cred.VerifyPassword(password) {
		return nil
	}
	assert.Fail(nil, "password mismatch")
	return nil
}

// ──────────────────────────────────────────────
// Credential lifecycle
// ──────────────────────────────────────────────

func TestCredential_IsVerified(t *testing.T) {
	cred := &Credential{Verified: false}
	assert.False(t, cred.IsVerified())
	cred.Verify()
	assert.True(t, cred.IsVerified())
	assert.NotNil(t, cred.VerifiedAt)
}

func TestCredential_MarkUsed(t *testing.T) {
	cred := &Credential{}
	assert.Nil(t, cred.LastUsedAt)
	cred.MarkUsed()
	assert.NotNil(t, cred.LastUsedAt)
}

func TestCredential_SoftDelete(t *testing.T) {
	cred := &Credential{}
	assert.False(t, cred.IsDeleted())
	cred.SoftDelete()
	assert.True(t, cred.IsDeleted())
}

// ──────────────────────────────────────────────
// NewCredential constructors
// ──────────────────────────────────────────────

func TestNewEmailCredential(t *testing.T) {
	cred := NewEmailCredential("acc-1", "test@example.com")
	assert.Equal(t, CredentialTypeEmail, cred.Type)
	assert.Equal(t, "test@example.com", *cred.Identifier)
	assert.False(t, cred.Verified)
}

func TestNewPhoneCredential(t *testing.T) {
	cred := NewPhoneCredential("acc-1", "+8613800138000")
	assert.Equal(t, CredentialTypePhone, cred.Type)
	assert.Equal(t, "+8613800138000", *cred.Identifier)
}
