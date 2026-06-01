package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rushairer/gosso/internal/audit/domain"
	"github.com/stretchr/testify/assert"
)

func TestLogNilReceiver(t *testing.T) {
	var auditor *Auditor
	record := &domain.AuditRecord{
		ID:        uuid.New(),
		TxID:      uuid.New(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}
	err := auditor.Log(context.Background(), record)
	assert.NoError(t, err)
}

func TestNewRecord(t *testing.T) {
	accountID := uuid.New()
	record := domain.NewRecord(
		domain.ActionLoginSuccess,
		"testuser",
		&accountID,
		json.RawMessage(`{"account_id":"`+accountID.String()+`"}`),
		json.RawMessage(`{"ip":"127.0.0.1"}`),
	)

	assert.Equal(t, domain.ActionLoginSuccess, record.Action)
	assert.Equal(t, "testuser", record.Actor)
	assert.NotNil(t, record.AccountID)
	assert.Equal(t, accountID, *record.AccountID)
	assert.NotEmpty(t, record.ID)
	assert.NotEmpty(t, record.TxID)
	assert.False(t, record.CreatedAt.IsZero())
}

func TestNewRecordNoAccount(t *testing.T) {
	record := domain.NewRecord(
		domain.ActionLoginFailure,
		"unknown",
		nil,
		json.RawMessage(`{"username":"unknown"}`),
		json.RawMessage(`{}`),
	)

	assert.Equal(t, domain.ActionLoginFailure, record.Action)
	assert.Nil(t, record.AccountID)
}

func TestActionConstants(t *testing.T) {
	assert.Equal(t, "auth.login.success", domain.ActionLoginSuccess)
	assert.Equal(t, "auth.login.failure", domain.ActionLoginFailure)
	assert.Equal(t, "auth.mfa_login.success", domain.ActionMFALoginSuccess)
	assert.Equal(t, "auth.mfa_login.failure", domain.ActionMFALoginFailure)
	assert.Equal(t, "auth.logout", domain.ActionLogout)
	assert.Equal(t, "account.register", domain.ActionAccountRegister)
	assert.Equal(t, "account.delete", domain.ActionAccountDelete)
	assert.Equal(t, "account.suspend", domain.ActionAccountSuspend)
	assert.Equal(t, "account.activate", domain.ActionAccountActivate)
	assert.Equal(t, "account.password.change", domain.ActionPasswordChange)
	assert.Equal(t, "account.password.reset", domain.ActionPasswordReset)
	assert.Equal(t, "account.role.assign", domain.ActionRoleAssign)
	assert.Equal(t, "account.role.remove", domain.ActionRoleRemove)
	assert.Equal(t, "account.mfa.activate", domain.ActionMFAActivate)
	assert.Equal(t, "account.mfa.disable", domain.ActionMFADisable)
}
