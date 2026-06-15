package domain

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
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
	assert.NoError(t, compareHashAndPassword(t, h1, "test"))
}

func TestHashPassword_DifferentInputs(t *testing.T) {
	h1, _ := HashPassword("password1")
	h2, _ := HashPassword("password2")
	assert.NotEqual(t, h1, h2)
}

// compareHashAndPassword is a test helper
func compareHashAndPassword(t *testing.T, hashed, password string) error {
	cred := &Credential{Type: CredentialTypePassword, Value: hashed}
	if cred.VerifyPassword(password) {
		return nil
	}
	assert.Fail(t, "password mismatch")
	return fmt.Errorf("password mismatch")
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
	err := cred.SoftDelete()
	assert.NoError(t, err)
	assert.True(t, cred.IsDeleted())
	err = cred.SoftDelete()
	assert.ErrorIs(t, err, ErrCredentialAlreadyDeleted)
}

// ──────────────────────────────────────────────
// NewCredential constructors
// ──────────────────────────────────────────────

func TestNewEmailCredential(t *testing.T) {
	cred, err := NewEmailCredential("acc-1", "test@example.com")
	require.NoError(t, err)
	assert.Equal(t, CredentialTypeEmail, cred.Type)
	assert.Equal(t, "test@example.com", *cred.Identifier)
	assert.False(t, cred.Verified)
}

func TestNewPhoneCredential(t *testing.T) {
	cred, err := NewPhoneCredential("acc-1", "+8613800138000")
	require.NoError(t, err)
	assert.Equal(t, CredentialTypePhone, cred.Type)
	assert.Equal(t, "+8613800138000", *cred.Identifier)
}

func TestNewCredential(t *testing.T) {
	email := "user@example.com"
	cred, err := NewCredential("acc-1", CredentialTypeTOTP, &email, "secret-value")
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.NotEmpty(t, cred.ID)
	assert.Equal(t, "acc-1", cred.AccountID)
	assert.Equal(t, CredentialTypeTOTP, cred.Type)
	assert.Equal(t, &email, cred.Identifier)
	assert.Equal(t, "secret-value", cred.Value)
	assert.False(t, cred.Verified)
	assert.NotNil(t, cred.Metadata)
	assert.False(t, cred.CreatedAt.IsZero())
}

// ──────────────────────────────────────────────
// MarshalLogObject
// ──────────────────────────────────────────────

func TestCredential_MarshalLogObject_ExcludesValue(t *testing.T) {
	cred, err := NewPasswordCredential("acc-1", "strong-password-123")
	require.NoError(t, err)

	enc := zapcore.NewMapObjectEncoder()
	err = cred.MarshalLogObject(enc)
	require.NoError(t, err)

	fields := enc.Fields

	// Value must NOT appear in log output
	_, hasValue := fields["value"]
	assert.False(t, hasValue, "Value field must not appear in log output")

	// Sensitive fields should be present
	assert.Equal(t, cred.ID, fields["id"])
	assert.Equal(t, "acc-1", fields["account_id"])
	assert.Equal(t, string(CredentialTypePassword), fields["credential_type"])
	assert.Equal(t, true, fields["verified"])
}

func TestCredential_MarshalLogObject_MasksIdentifier(t *testing.T) {
	email := "user@example.com"
	cred := &Credential{
		Type:       CredentialTypeEmail,
		Identifier: &email,
	}

	enc := zapcore.NewMapObjectEncoder()
	err := cred.MarshalLogObject(enc)
	require.NoError(t, err)

	// Identifier should be masked
	identifier := enc.Fields["identifier"].(string)
	assert.True(t, strings.Contains(identifier, "***"), "identifier should be masked: %s", identifier)
	assert.NotEqual(t, email, identifier, "raw email must not appear in log output")
}

func TestCredential_MarshalLogObject_NilIdentifier(t *testing.T) {
	cred := &Credential{
		Type: CredentialTypePassword,
	}

	enc := zapcore.NewMapObjectEncoder()
	err := cred.MarshalLogObject(enc)
	require.NoError(t, err)

	// Nil identifier should not be present in fields
	_, hasIdentifier := enc.Fields["identifier"]
	assert.False(t, hasIdentifier, "nil identifier should not be logged")
}

func TestIsValidCredentialType(t *testing.T) {
	assert.True(t, IsValidCredentialType(CredentialTypePassword))
	assert.True(t, IsValidCredentialType(CredentialTypeEmail))
	assert.True(t, IsValidCredentialType(CredentialTypePhone))
	assert.True(t, IsValidCredentialType(CredentialTypeTOTP))
	assert.True(t, IsValidCredentialType(CredentialTypeWebAuthn))
	assert.True(t, IsValidCredentialType(CredentialTypeBackupCode))
	assert.False(t, IsValidCredentialType(""))
	assert.False(t, IsValidCredentialType("unknown"))
}
