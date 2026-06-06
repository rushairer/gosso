package domain

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// NewRecord
// ──────────────────────────────────────────────

func TestNewRecord_BasicFields(t *testing.T) {
	resource := json.RawMessage(`{"user":"test"}`)
	meta := json.RawMessage(`{"ip":"127.0.0.1"}`)

	record := NewRecord(ActionLoginSuccess, "system", nil, resource, meta)

	assert.Equal(t, ActionLoginSuccess, record.Action)
	assert.Equal(t, "system", record.Actor)
	assert.Nil(t, record.AccountID)
	assert.Equal(t, resource, record.Resource)
	assert.Equal(t, meta, record.Meta)
	assert.Nil(t, record.Old)
	assert.Nil(t, record.New)
	assert.False(t, record.CreatedAt.IsZero())
}

func TestNewRecord_WithAccountID(t *testing.T) {
	accountID := uuid.New().String()
	resource := json.RawMessage(`{}`)

	record := NewRecord(ActionAccountRegister, "user", &accountID, resource, nil)

	require.NotNil(t, record.AccountID)
	assert.Equal(t, accountID, *record.AccountID)
}

func TestNewRecord_GeneratesUniqueIDs(t *testing.T) {
	resource := json.RawMessage(`{}`)

	r1 := NewRecord(ActionLoginSuccess, "system", nil, resource, nil)
	r2 := NewRecord(ActionLoginSuccess, "system", nil, resource, nil)

	assert.NotEqual(t, r1.ID, r2.ID)
	assert.NotEqual(t, r1.TxID, r2.TxID)
	assert.NotEqual(t, r1.ID, r1.TxID)
}

func TestNewRecord_UUIDFormat(t *testing.T) {
	resource := json.RawMessage(`{}`)

	record := NewRecord(ActionLoginSuccess, "system", nil, resource, nil)

	_, err := uuid.Parse(record.ID)
	assert.NoError(t, err)
	_, err = uuid.Parse(record.TxID)
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// Action constants
// ──────────────────────────────────────────────

func TestActionConstants(t *testing.T) {
	assert.Equal(t, "auth.login.success", ActionLoginSuccess)
	assert.Equal(t, "auth.login.failure", ActionLoginFailure)
	assert.Equal(t, "auth.mfa_login.success", ActionMFALoginSuccess)
	assert.Equal(t, "auth.mfa_login.failure", ActionMFALoginFailure)
	assert.Equal(t, "auth.logout", ActionLogout)

	assert.Equal(t, "account.register", ActionAccountRegister)
	assert.Equal(t, "account.delete", ActionAccountDelete)
	assert.Equal(t, "account.suspend", ActionAccountSuspend)
	assert.Equal(t, "account.activate", ActionAccountActivate)
	assert.Equal(t, "account.password.change", ActionPasswordChange)
	assert.Equal(t, "account.password.reset", ActionPasswordReset)

	assert.Equal(t, "account.role.assign", ActionRoleAssign)
	assert.Equal(t, "account.role.remove", ActionRoleRemove)

	assert.Equal(t, "account.mfa.activate", ActionMFAActivate)
	assert.Equal(t, "account.mfa.disable", ActionMFADisable)

	assert.Equal(t, "auth.passkey.register", ActionPasskeyRegister)
	assert.Equal(t, "auth.passkey.login", ActionPasskeyLogin)
	assert.Equal(t, "auth.passkey.delete", ActionPasskeyDelete)
}

func TestActionConstants_Unique(t *testing.T) {
	actions := []string{
		ActionLoginSuccess, ActionLoginFailure,
		ActionMFALoginSuccess, ActionMFALoginFailure,
		ActionLogout,
		ActionAccountRegister, ActionAccountDelete,
		ActionAccountSuspend, ActionAccountActivate,
		ActionPasswordChange, ActionPasswordReset,
		ActionRoleAssign, ActionRoleRemove,
		ActionMFAActivate, ActionMFADisable,
		ActionPasskeyRegister, ActionPasskeyLogin, ActionPasskeyDelete,
	}

	seen := make(map[string]bool)
	for _, a := range actions {
		assert.False(t, seen[a], "duplicate action: %s", a)
		seen[a] = true
	}
	assert.Len(t, seen, 18)
}
