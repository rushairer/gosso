package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// mockWebAuthnRepo implements repository.WebAuthnCredentialRepository for testing
type mockWebAuthnRepo struct {
	creds map[string][]*domain.WebAuthnCredential // key: accountID
}

func (m *mockWebAuthnRepo) CreateCredential(_ context.Context, _ *sql.Tx, _ *domain.WebAuthnCredential) error {
	return nil
}

func (m *mockWebAuthnRepo) FindByCredentialID(_ context.Context, _ string) (*domain.WebAuthnCredential, error) {
	return nil, nil
}

func (m *mockWebAuthnRepo) FindByAccountID(_ context.Context, accountID string) ([]*domain.WebAuthnCredential, error) {
	if creds, ok := m.creds[accountID]; ok {
		return creds, nil
	}
	return nil, nil
}

func (m *mockWebAuthnRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *domain.WebAuthnCredential) error {
	return nil
}

func (m *mockWebAuthnRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func (m *mockWebAuthnRepo) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func newTestPasskeyService(credRepo *mockWebAuthnRepo) *PasskeyService {
	return &PasskeyService{
		credRepo: credRepo,
		logger:   zap.NewNop(),
	}
}

// ──────────────────────────────────────────────
// HasPasskeys
// ──────────────────────────────────────────────

func TestHasPasskeys_True(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		creds: map[string][]*domain.WebAuthnCredential{
			"account-001": {
				{ID: "cred-1", AccountID: "account-001", Name: "My Passkey"},
			},
		},
	}
	svc := newTestPasskeyService(credRepo)

	has, err := svc.HasPasskeys(context.Background(), "account-001")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestHasPasskeys_False(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc := newTestPasskeyService(credRepo)

	has, err := svc.HasPasskeys(context.Background(), "account-001")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestHasPasskeys_Error(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: nil} // nil map → will return nil slice
	svc := newTestPasskeyService(credRepo)

	has, err := svc.HasPasskeys(context.Background(), "account-001")
	require.NoError(t, err)
	assert.False(t, has)
}

// ──────────────────────────────────────────────
// ListCredentials
// ──────────────────────────────────────────────

func TestListCredentials_Success(t *testing.T) {
	now := time.Now()
	lastUsed := now.Add(-1 * time.Hour)
	credRepo := &mockWebAuthnRepo{
		creds: map[string][]*domain.WebAuthnCredential{
			"account-001": {
				{
					ID:              "cred-1",
					AccountID:       "account-001",
					Name:            "MacBook Pro",
					CreatedAt:       now,
					LastUsedAt:      &lastUsed,
					AttestationType: "none",
					Transports:      []string{"internal"},
				},
				{
					ID:              "cred-2",
					AccountID:       "account-001",
					Name:            "iPhone",
					CreatedAt:       now,
					AttestationType: "none",
				},
			},
		},
	}
	svc := newTestPasskeyService(credRepo)

	views, err := svc.ListCredentials(context.Background(), "account-001")
	require.NoError(t, err)
	require.Len(t, views, 2)

	assert.Equal(t, "cred-1", views[0].ID)
	assert.Equal(t, "MacBook Pro", views[0].Name)
	assert.NotNil(t, views[0].LastUsedAt)
	assert.Equal(t, []string{"internal"}, views[0].Transports)

	assert.Equal(t, "cred-2", views[1].ID)
	assert.Equal(t, "iPhone", views[1].Name)
	assert.Nil(t, views[1].LastUsedAt)
}

func TestListCredentials_Empty(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc := newTestPasskeyService(credRepo)

	views, err := svc.ListCredentials(context.Background(), "account-001")
	require.NoError(t, err)
	assert.Empty(t, views)
}

// ──────────────────────────────────────────────
// NewPasskeyService
// ──────────────────────────────────────────────

func TestNewPasskeyService_NilLogger(t *testing.T) {
	svc := NewPasskeyService(nil, nil, nil, nil, nil, nil)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
}
