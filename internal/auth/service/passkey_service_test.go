package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/auth/domain"
	"github.com/rushairer/gosso/internal/testutil"
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
	// findByAccountIDErr forces FindByAccountID to return this error when set.
	findByAccountIDErr error
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
	if m.findByAccountIDErr != nil {
		return nil, m.findByAccountIDErr
	}
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

// ──────────────────────────────────────────────
// BeginLogin / BeginMFALogin — no credentials / repo error
// ──────────────────────────────────────────────

func TestBeginLogin_NoCredentials(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc := newTestPasskeyService(credRepo)

	_, _, err := svc.BeginLogin(context.Background(), "acct-1")
	assert.ErrorIs(t, err, ErrPasskeyNotFound)
}

func TestBeginLogin_RepoError(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		findByAccountIDErr: errors.New("db failure"),
	}
	svc := newTestPasskeyService(credRepo)

	_, _, err := svc.BeginLogin(context.Background(), "acct-1")
	assert.ErrorIs(t, err, ErrPasskeyNotFound)
}

func TestBeginMFALogin_NoCredentials(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc := newTestPasskeyService(credRepo)

	_, _, err := svc.BeginMFALogin(context.Background(), "acct-1")
	assert.ErrorIs(t, err, ErrPasskeyNotFound)
}

func TestBeginMFALogin_RepoError(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		findByAccountIDErr: errors.New("db failure"),
	}
	svc := newTestPasskeyService(credRepo)

	_, _, err := svc.BeginMFALogin(context.Background(), "acct-1")
	assert.ErrorIs(t, err, ErrPasskeyNotFound)
}

// ──────────────────────────────────────────────
// CompleteRegistration / CompleteLogin / CompleteMFALogin — missing challenge
// ──────────────────────────────────────────────

func TestCompleteRegistration_MissingChallenge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc := &PasskeyService{
		credRepo: credRepo,
		redis:    redisClient,
		logger:   zap.NewNop(),
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	_, err := svc.CompleteRegistration(context.Background(), "acct-1", "alice", "Alice", req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal session data")
}

func TestCompleteLogin_MissingChallenge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc := &PasskeyService{
		redis:  redisClient,
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	_, _, err := svc.CompleteLogin(context.Background(), "nonexistent-request-id", req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal session data")
}

func TestCompleteMFALogin_MissingChallenge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc := &PasskeyService{
		redis:  redisClient,
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	err := svc.CompleteMFALogin(context.Background(), "nonexistent-request-id", "acct-1", req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal session data")
}

// ──────────────────────────────────────────────
// CompleteLogin / CompleteMFALogin — request body too large
// ──────────────────────────────────────────────

func storeSessionDataInRedis(t *testing.T, svc *PasskeyService, key string) {
	t.Helper()
	sessionData := wa.SessionData{Challenge: "test-challenge"}
	data, err := json.Marshal(sessionData)
	require.NoError(t, err)
	err = svc.redis.Set(context.Background(), key, data, 5*time.Minute)
	require.NoError(t, err)
}

func TestCompleteLogin_RequestBodyTooLarge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc := &PasskeyService{
		redis:  redisClient,
		logger: zap.NewNop(),
	}

	requestID := "test-req-id"
	storeSessionDataInRedis(t, svc, fmt.Sprintf("webauthn:login:%s", requestID))

	largeBody := strings.NewReader(strings.Repeat("A", maxPasskeyRequestBodySize+1))
	req := httptest.NewRequest(http.MethodPost, "/", largeBody)

	_, _, err := svc.CompleteLogin(context.Background(), requestID, req)
	assert.ErrorIs(t, err, ErrRequestBodyTooLarge)
}

func TestCompleteMFALogin_RequestBodyTooLarge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc := &PasskeyService{
		redis:  redisClient,
		logger: zap.NewNop(),
	}

	requestID := "test-req-id"
	storeSessionDataInRedis(t, svc, fmt.Sprintf("webauthn:mfa:%s", requestID))

	largeBody := strings.NewReader(strings.Repeat("A", maxPasskeyRequestBodySize+1))
	req := httptest.NewRequest(http.MethodPost, "/", largeBody)

	err := svc.CompleteMFALogin(context.Background(), requestID, "acct-1", req)
	// Characterization: CompleteMFALogin uses errors.New instead of ErrRequestBodyTooLarge sentinel
	assert.ErrorContains(t, err, "request body too large")
}

// ──────────────────────────────────────────────
// Begin* — happy paths with real webauthn + miniredis
// ──────────────────────────────────────────────

func newTestPasskeyServiceWithRedis(t *testing.T, credRepo *mockWebAuthnRepo) (*PasskeyService, *miniredis.Miniredis) {
	t.Helper()
	redisClient, mr := testutil.SetupTestRedis(t)

	web, err := wa.New(&wa.Config{
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"http://localhost"},
	})
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create webauthn instance: %v", err)
	}

	svc := &PasskeyService{
		web:          web,
		credRepo:     credRepo,
		redis:        redisClient,
		logger:       zap.NewNop(),
		challengeTTL: 5 * time.Minute,
	}
	return svc, mr
}

func TestBeginRegistration_Success(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc, mr := newTestPasskeyServiceWithRedis(t, credRepo)
	defer mr.Close()

	cc, err := svc.BeginRegistration(context.Background(), "acct-1", "alice", "Alice Smith")
	require.NoError(t, err)
	require.NotNil(t, cc)
	assert.NotNil(t, cc.Response)

	exists, err := svc.redis.Exists(context.Background(), "webauthn:reg:acct-1")
	require.NoError(t, err)
	assert.True(t, exists, "challenge should be stored in Redis")
}

func TestBeginRegistration_WithExistingCreds(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		creds: map[string][]*domain.WebAuthnCredential{
			"acct-1": {
				{ID: "existing", AccountID: "acct-1", CredentialID: []byte("cred-id-1"), Name: "Old Passkey"},
			},
		},
	}
	svc, mr := newTestPasskeyServiceWithRedis(t, credRepo)
	defer mr.Close()

	cc, err := svc.BeginRegistration(context.Background(), "acct-1", "alice", "Alice Smith")
	require.NoError(t, err)
	require.NotNil(t, cc)
}

func TestBeginLogin_Success(t *testing.T) {
	credRepo := &mockWebAuthnRepo{
		creds: map[string][]*domain.WebAuthnCredential{
			"acct-1": {
				{ID: "cred-1", AccountID: "acct-1", CredentialID: []byte("cred-id"), PublicKey: []byte("pub-key")},
			},
		},
	}
	svc, mr := newTestPasskeyServiceWithRedis(t, credRepo)
	defer mr.Close()

	assertion, requestID, err := svc.BeginLogin(context.Background(), "acct-1")
	require.NoError(t, err)
	require.NotNil(t, assertion)
	assert.NotEmpty(t, requestID)

	exists, err := svc.redis.Exists(context.Background(), fmt.Sprintf("webauthn:login:%s", requestID))
	require.NoError(t, err)
	assert.True(t, exists, "challenge should be stored in Redis")
}

func TestBeginDiscoverableLogin_Success(t *testing.T) {
	credRepo := &mockWebAuthnRepo{creds: map[string][]*domain.WebAuthnCredential{}}
	svc, mr := newTestPasskeyServiceWithRedis(t, credRepo)
	defer mr.Close()

	assertion, requestID, err := svc.BeginDiscoverableLogin(context.Background())
	require.NoError(t, err)
	require.NotNil(t, assertion)
	assert.NotEmpty(t, requestID)

	exists, err := svc.redis.Exists(context.Background(), fmt.Sprintf("webauthn:login:%s", requestID))
	require.NoError(t, err)
	assert.True(t, exists, "challenge should be stored in Redis")
}
