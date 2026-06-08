package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/auth/domain"
)

// newTestPasskeyServiceWithDB creates a PasskeyService that uses a sqlmock DB.
func newTestPasskeyServiceWithDB(t *testing.T, credRepo *mockWebAuthnRepo, sqlDB *sql.DB) *PasskeyService {
	t.Helper()
	return &PasskeyService{
		credRepo: credRepo,
		db:       sqlDB,
		logger:   zap.NewNop(),
	}
}

// mockWebAuthnRepo implements repository.WebAuthnCredentialRepository for testing
type mockWebAuthnRepo struct {
	creds map[string][]*domain.WebAuthnCredential // key: accountID
	// findByCredentialIDFn overrides FindByCredentialID when set.
	findByCredentialIDFn func(ctx context.Context, credentialID string) (*domain.WebAuthnCredential, error)
}

func (m *mockWebAuthnRepo) CreateCredential(_ context.Context, _ *sql.Tx, _ *domain.WebAuthnCredential) error {
	return nil
}

func (m *mockWebAuthnRepo) FindByCredentialID(_ context.Context, _ string) (*domain.WebAuthnCredential, error) {
	if m.findByCredentialIDFn != nil {
		return m.findByCredentialIDFn(context.Background(), "")
	}
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

type mockAccountLookupForPasskey struct {
	account *accountDomain.Account
	err     error
}

func (m *mockAccountLookupForPasskey) FindAccountByID(_ context.Context, _ string) (*accountDomain.Account, error) {
	return m.account, m.err
}

// ──────────────────────────────────────────────
// toCredentialSlice
// ──────────────────────────────────────────────

func TestToCredentialSlice_Nil(t *testing.T) {
	result := toCredentialSlice(nil)
	assert.Nil(t, result)
}

func TestToCredentialSlice_Empty(t *testing.T) {
	result := toCredentialSlice([]*domain.WebAuthnCredential{})
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestToCredentialSlice_Data(t *testing.T) {
	input := []*domain.WebAuthnCredential{
		{ID: "cred-1", AccountID: "acct-1"},
		{ID: "cred-2", AccountID: "acct-2"},
	}
	result := toCredentialSlice(input)
	require.Len(t, result, 2)
	assert.Equal(t, "cred-1", result[0].ID)
	assert.Equal(t, "acct-2", result[1].AccountID)
}

// ──────────────────────────────────────────────
// transportsToStrings
// ──────────────────────────────────────────────

func TestTransportsToStrings_Nil(t *testing.T) {
	result := transportsToStrings(nil)
	assert.Nil(t, result)
}

func TestTransportsToStrings_Empty(t *testing.T) {
	result := transportsToStrings([]protocol.AuthenticatorTransport{})
	assert.Nil(t, result)
}

func TestTransportsToStrings_Data(t *testing.T) {
	input := []protocol.AuthenticatorTransport{
		protocol.USB,
		protocol.Internal,
	}
	result := transportsToStrings(input)
	require.Len(t, result, 2)
	assert.Equal(t, "usb", result[0])
	assert.Equal(t, "internal", result[1])
}

// ──────────────────────────────────────────────
// SetChallengeTTL
// ──────────────────────────────────────────────

func TestPasskeyService_SetChallengeTTL(t *testing.T) {
	svc := &PasskeyService{challengeTTL: defaultChallengeTTL, logger: zap.NewNop()}
	assert.Equal(t, defaultChallengeTTL, svc.challengeTTL)
	svc.SetChallengeTTL(10 * time.Minute)
	assert.Equal(t, 10*time.Minute, svc.challengeTTL)
}

func TestPasskeyService_SetChallengeTTL_ZeroIgnored(t *testing.T) {
	svc := &PasskeyService{challengeTTL: defaultChallengeTTL, logger: zap.NewNop()}
	svc.SetChallengeTTL(0)
	assert.Equal(t, defaultChallengeTTL, svc.challengeTTL)
}

// ──────────────────────────────────────────────
// ResolveAccountForRegistration
// ──────────────────────────────────────────────

func TestResolveAccountForRegistration_WithUsernameAndDisplayName(t *testing.T) {
	userName := "alice"
	account := &accountDomain.Account{
		ID:          "acct-1",
		Username:    &userName,
		DisplayName: "Alice Smith",
	}
	svc := &PasskeyService{
		accountLookup: &mockAccountLookupForPasskey{account: account},
		logger:        zap.NewNop(),
	}
	username, displayName, err := svc.ResolveAccountForRegistration(context.Background(), "acct-1")
	require.NoError(t, err)
	assert.Equal(t, "alice", username)
	assert.Equal(t, "Alice Smith", displayName)
}

func TestResolveAccountForRegistration_FallbackToAccountID(t *testing.T) {
	account := &accountDomain.Account{
		ID: "acct-2",
	}
	svc := &PasskeyService{
		accountLookup: &mockAccountLookupForPasskey{account: account},
		logger:        zap.NewNop(),
	}
	username, displayName, err := svc.ResolveAccountForRegistration(context.Background(), "acct-2")
	require.NoError(t, err)
	assert.Equal(t, "acct-2", username)
	assert.Equal(t, "acct-2", displayName)
}

func TestResolveAccountForRegistration_AccountNotFound(t *testing.T) {
	svc := &PasskeyService{
		accountLookup: &mockAccountLookupForPasskey{err: errors.New("not found")},
		logger:        zap.NewNop(),
	}
	_, _, err := svc.ResolveAccountForRegistration(context.Background(), "acct-999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolve account")
}

// ──────────────────────────────────────────────
// DeleteCredential
// ──────────────────────────────────────────────

func TestDeleteCredential_NotFound(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		findByCredentialIDFn: func(_ context.Context, _ string) (*domain.WebAuthnCredential, error) {
			return nil, errors.New("not found")
		},
	}
	svc := newTestPasskeyService(credRepo)

	err := svc.DeleteCredential(context.Background(), "acct-1", "cred-999")
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestDeleteCredential_WrongAccount(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		findByCredentialIDFn: func(_ context.Context, _ string) (*domain.WebAuthnCredential, error) {
			return &domain.WebAuthnCredential{ID: "cred-1", AccountID: "acct-owner"}, nil
		},
	}
	svc := newTestPasskeyService(credRepo)

	err := svc.DeleteCredential(context.Background(), "acct-other", "cred-1")
	assert.ErrorIs(t, err, ErrCredentialOwnership)
}

func TestDeleteCredential_Success(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	credRepo := &mockWebAuthnRepo{
		findByCredentialIDFn: func(_ context.Context, _ string) (*domain.WebAuthnCredential, error) {
			return &domain.WebAuthnCredential{ID: "cred-1", AccountID: "acct-1"}, nil
		},
	}
	svc := newTestPasskeyServiceWithDB(t, credRepo, sqlDB)

	err = svc.DeleteCredential(context.Background(), "acct-1", "cred-1")
	assert.NoError(t, err)
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
