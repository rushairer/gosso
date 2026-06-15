package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// NewAccount
// ──────────────────────────────────────────────

func TestNewAccount(t *testing.T) {
	a, _ := NewAccount("John Doe")
	assert.NotEmpty(t, a.ID)
	assert.Equal(t, "John Doe", a.DisplayName)
	assert.Equal(t, AccountStatusActive, a.Status)
	assert.Equal(t, "en", a.Locale)
	assert.Equal(t, "UTC", a.Timezone)
	assert.NotNil(t, a.Metadata)
	assert.False(t, a.CreatedAt.IsZero())
}

// ──────────────────────────────────────────────
// IsActive / IsDeleted / IsSuspended
// ──────────────────────────────────────────────

func TestAccount_IsActive_Default(t *testing.T) {
	a, _ := NewAccount("Test")
	assert.True(t, a.IsActive())
	assert.False(t, a.IsDeleted())
	assert.False(t, a.IsSuspended())
}

func TestAccount_IsActive_Suspended(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.Suspend())
	assert.False(t, a.IsActive())
	assert.True(t, a.IsSuspended())
}

func TestAccount_IsActive_Deleted(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.SoftDelete())
	assert.False(t, a.IsActive())
	assert.True(t, a.IsDeleted())
	assert.Equal(t, AccountStatusDeleted, a.Status)
}

func TestAccount_Activate(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.Suspend())
	require.NoError(t, a.Activate())
	assert.True(t, a.IsActive())
	assert.Equal(t, AccountStatusActive, a.Status)
}

// ──────────────────────────────────────────────
// SoftDelete / Suspend / Activate
// ──────────────────────────────────────────────

func TestAccount_SoftDelete_SetsFields(t *testing.T) {
	a, _ := NewAccount("Test")
	before := time.Now()
	require.NoError(t, a.SoftDelete())

	assert.NotNil(t, a.DeletedAt)
	assert.True(t, a.DeletedAt.After(before) || a.DeletedAt.Equal(before))
	assert.Equal(t, AccountStatusDeleted, a.Status)
}

func TestAccount_Suspend_SetsStatus(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.Suspend())
	assert.Equal(t, AccountStatusSuspended, a.Status)
}

func TestAccount_Activate_FromSuspended(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.Suspend())
	require.NoError(t, a.Activate())
	assert.Equal(t, AccountStatusActive, a.Status)
}

// ──────────────────────────────────────────────
// Invalid state transitions
// ──────────────────────────────────────────────

func TestAccount_Suspend_AlreadySuspended(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.Suspend())
	err := a.Suspend()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAccountStatus))
}

func TestAccount_Suspend_Deleted(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.SoftDelete())
	err := a.Suspend()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCannotSuspendDeleted))
}

func TestAccount_Activate_AlreadyActive(t *testing.T) {
	a, _ := NewAccount("Test")
	err := a.Activate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAccountStatus))
}

func TestAccount_Activate_Deleted(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.SoftDelete())
	err := a.Activate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCannotActivateDeleted))
}

func TestAccount_SoftDelete_AlreadyDeleted(t *testing.T) {
	a, _ := NewAccount("Test")
	require.NoError(t, a.SoftDelete())
	err := a.SoftDelete()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccountAlreadyDeleted))
}

func TestIsValidAccountStatus(t *testing.T) {
	assert.True(t, IsValidAccountStatus(AccountStatusActive))
	assert.True(t, IsValidAccountStatus(AccountStatusSuspended))
	assert.True(t, IsValidAccountStatus(AccountStatusDeleted))
	assert.False(t, IsValidAccountStatus(""))
	assert.False(t, IsValidAccountStatus("unknown"))
}

func TestAccount_Validate_InvalidStatus(t *testing.T) {
	a, _ := NewAccount("Test")
	a.Status = AccountStatus("invalid")
	err := a.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAccountStatus))
}
