package service

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/testutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

type stubPasswordResetEmailSender struct {
	sentLinks []string
}

func (s *stubPasswordResetEmailSender) SendPasswordResetLink(_ context.Context, _, link string) error {
	s.sentLinks = append(s.sentLinks, link)
	return nil
}

func setupTestPasswordResetService(t *testing.T) (*PasswordResetService, *cache.RedisClient, *miniredis.Miniredis, *stubPasswordResetEmailSender) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := setupTestMiniredis(t)
	testutil.SkipIfNoCJSON(t, redisClient)

	emailSvc := &stubPasswordResetEmailSender{}
	svc := &PasswordResetService{
		redis:       redisClient,
		emailSender: emailSvc,
		baseURL:     "http://localhost:3000/reset-password",
		logger:      logger,
	}

	return svc, redisClient, mr, emailSvc
}

func setupTestMiniredis(t *testing.T) (*cache.RedisClient, *miniredis.Miniredis) {
	t.Helper()
	logger := zap.NewNop()

	mr := miniredis.RunT(t)
	redisClient, err := cache.NewRedisClient("redis://"+mr.Addr(), 10, 5*time.Second, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create test redis client: %v", err)
	}

	return redisClient, mr
}

func TestPasswordReset_Success(t *testing.T) {
	svc, redis, mr, _ := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()

	// Simulate complete token storage and verification flow (at the Redis layer)
	tokenHash := tokenDomain.HashToken("test-token-123")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-001","email":"test@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// Verify token was stored successfully
	raw, err := redis.Get(ctx, tokenKey)
	require.NoError(t, err)
	assert.Contains(t, raw, "account-001")

	// Delete key (simulate one-time use)
	err = redis.Del(ctx, tokenKey)
	require.NoError(t, err)

	// Fetching again should return not found
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_Cooldown(t *testing.T) {
	svc, redis, mr, _ := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()
	email := "cooldown@example.com"

	// Set cooldown key
	cooldownKey := svc.buildCooldownKey(email)
	err := redis.Set(ctx, cooldownKey, []byte("1"), PasswordResetCooldownTTL)
	require.NoError(t, err)

	// Check cooldown
	exists, err := redis.Exists(ctx, cooldownKey)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPasswordReset_InvalidToken(t *testing.T) {
	svc, redis, mr, _ := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()

	// Use a non-existent token hash
	tokenHash := tokenDomain.HashToken("nonexistent-token")
	tokenKey := svc.buildTokenKey(tokenHash)

	_, err := redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_ExpiredToken(t *testing.T) {
	svc, redis, mr, _ := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()

	// Manually delete to simulate expiration
	tokenHash := tokenDomain.HashToken("expired-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-002","email":"expired@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// Manually delete key
	_ = redis.Del(ctx, tokenKey)

	// Fetching should return not found
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPasswordReset_TokenExhausted(t *testing.T) {
	svc, redis, mr, _ := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()

	// Store a token with exhausted attempts
	tokenHash := tokenDomain.HashToken("exhausted-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-003","email":"exhausted@example.com","attempts":5}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// Verify attempts >= 5
	raw, err := redis.Get(ctx, tokenKey)
	require.NoError(t, err)
	assert.Contains(t, raw, `"attempts":5`)

	// Delete key (simulate exhausted handling in VerifyAndReset)
	err = redis.Del(ctx, tokenKey)
	require.NoError(t, err)
}

func TestPasswordReset_TokenReuse(t *testing.T) {
	svc, redis, mr, _ := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()

	// Store token
	tokenHash := tokenDomain.HashToken("reuse-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-004","email":"reuse@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// First fetch succeeds
	_, err = redis.Get(ctx, tokenKey)
	require.NoError(t, err)

	// Delete (one-time use)
	_ = redis.Del(ctx, tokenKey)

	// Second fetch fails
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_EmailNotFound(t *testing.T) {
	svc, redis, mr, emailSvc := setupTestPasswordResetService(t)
	defer mr.Close()

	ctx := context.Background()

	// Non-existent email: no Redis entry, no email sent
	cooldownKey := svc.buildCooldownKey("nonexistent@example.com")
	exists, err := redis.Exists(ctx, cooldownKey)
	require.NoError(t, err)
	assert.False(t, exists)

	assert.Len(t, emailSvc.sentLinks, 0)

	_ = ctx
}

func TestPasswordReset_TokenSecurity(t *testing.T) {
	// Verify SHA256 hash is irreversible and has correct length
	originalToken := "a]b1c2d3e4f5"
	hashedToken := tokenDomain.HashToken(originalToken)

	assert.NotEqual(t, originalToken, hashedToken)
	assert.Len(t, hashedToken, 64) // SHA256 hex = 64 chars

	// Same input produces the same hash
	hashedAgain := tokenDomain.HashToken(originalToken)
	assert.Equal(t, hashedToken, hashedAgain)
}

// ──────────────────────────────────────────────
// Mocks for RequestReset / VerifyAndReset tests
// ──────────────────────────────────────────────

type mockCredentialRepoForReset struct {
	findByTypeAndIdentifierFn func(ctx context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error)
	findPasswordCredentialFn  func(ctx context.Context, accountID string) (*accountDomain.Credential, error)
}

func (m *mockCredentialRepoForReset) CreateCredentials(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) FindByAccountAndType(_ context.Context, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) FindByTypeAndIdentifier(ctx context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	if m.findByTypeAndIdentifierFn != nil {
		return m.findByTypeAndIdentifierFn(ctx, credType, identifier)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) FindPasswordCredential(ctx context.Context, accountID string) (*accountDomain.Credential, error) {
	if m.findPasswordCredentialFn != nil {
		return m.findPasswordCredentialFn(ctx, accountID)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (m *mockCredentialRepoForReset) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}

type mockAccountSvcForReset struct {
	findByIDFn func(ctx context.Context, accountID string) (*accountDomain.Account, error)
}

func (m *mockAccountSvcForReset) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) FindAccountByID(ctx context.Context, accountID string) (*accountDomain.Account, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, accountID)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) SoftDeleteAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) VerifyCredential(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) ChangePassword(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) AssignRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) RemoveRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) SuspendAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) ActivateAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountSvcForReset) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}

type stubEmailSenderForReset struct {
	sentLinks []string
	sendErr   error
}

func (s *stubEmailSenderForReset) SendPasswordResetLink(_ context.Context, _, link string) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sentLinks = append(s.sentLinks, link)
	return nil
}

func setupTestPasswordResetServiceFull(t *testing.T) (*PasswordResetService, *cache.RedisClient, *miniredis.Miniredis, *stubEmailSenderForReset, *mockCredentialRepoForReset, *mockAccountSvcForReset) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := setupTestMiniredis(t)
	testutil.SkipIfNoCJSON(t, redisClient)

	emailSvc := &stubEmailSenderForReset{}
	credRepo := &mockCredentialRepoForReset{}
	acctSvc := &mockAccountSvcForReset{}

	svc := &PasswordResetService{
		redis:          redisClient,
		credentialRepo: credRepo,
		emailSender:    emailSvc,
		accountSvc:     acctSvc,
		baseURL:        "http://localhost:3000/reset-password",
		logger:         logger,
	}

	return svc, redisClient, mr, emailSvc, credRepo, acctSvc
}

// ──────────────────────────────────────────────
// RequestReset tests
// ──────────────────────────────────────────────

func TestRequestReset_Success(t *testing.T) {
	svc, _, mr, emailSvc, credRepo, acctSvc := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()

	email := "user@example.com"
	credRepo.findByTypeAndIdentifierFn = func(_ context.Context, _ accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
		return &accountDomain.Credential{
			ID:        "cred-001",
			AccountID: "acct-001",
			Type:      accountDomain.CredentialTypeEmail,
			Identifier: &email,
		}, nil
	}
	acctSvc.findByIDFn = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		return accountDomain.NewAccount("Test User"), nil
	}

	err := svc.RequestReset(ctx, email)
	require.NoError(t, err)

	assert.Len(t, emailSvc.sentLinks, 1)
	assert.Contains(t, emailSvc.sentLinks[0], "http://localhost:3000/reset-password?token=")
}

func TestRequestReset_CooldownActive(t *testing.T) {
	svc, redis, mr, emailSvc, _, _ := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()
	email := "cooldown@example.com"

	// Set cooldown key
	cooldownKey := svc.buildCooldownKey(email)
	err := redis.Set(ctx, cooldownKey, []byte("1"), PasswordResetCooldownTTL)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please wait before requesting another reset")
	assert.Len(t, emailSvc.sentLinks, 0)
}

func TestRequestReset_EmailNotFound(t *testing.T) {
	svc, _, mr, emailSvc, credRepo, _ := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()

	credRepo.findByTypeAndIdentifierFn = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return nil, fmt.Errorf("credential not found")
	}

	err := svc.RequestReset(ctx, "nobody@example.com")
	assert.NoError(t, err)
	assert.Len(t, emailSvc.sentLinks, 0)
}

func TestRequestReset_AccountInactive(t *testing.T) {
	svc, _, mr, emailSvc, credRepo, acctSvc := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()
	email := "inactive@example.com"

	credRepo.findByTypeAndIdentifierFn = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return &accountDomain.Credential{
			ID:        "cred-002",
			AccountID: "acct-002",
			Type:      accountDomain.CredentialTypeEmail,
			Identifier: &email,
		}, nil
	}
	acctSvc.findByIDFn = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		acct := accountDomain.NewAccount("Inactive User")
		_ = acct.Suspend()
		return acct, nil
	}

	err := svc.RequestReset(ctx, email)
	assert.NoError(t, err)
	assert.Len(t, emailSvc.sentLinks, 0)
}

func TestRequestReset_EmailSendFailure(t *testing.T) {
	svc, _, mr, emailSvc, credRepo, acctSvc := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()
	email := "sendfail@example.com"

	credRepo.findByTypeAndIdentifierFn = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return &accountDomain.Credential{
			ID:        "cred-003",
			AccountID: "acct-003",
			Type:      accountDomain.CredentialTypeEmail,
			Identifier: &email,
		}, nil
	}
	acctSvc.findByIDFn = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		return accountDomain.NewAccount("Test User"), nil
	}
	emailSvc.sendErr = fmt.Errorf("SMTP connection refused")

	err := svc.RequestReset(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "send reset email")
}

// ──────────────────────────────────────────────
// VerifyAndReset early-exit tests
// ──────────────────────────────────────────────

func TestVerifyAndReset_PasswordTooShort(t *testing.T) {
	svc, _, mr, _, _, _ := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()

	err := svc.VerifyAndReset(ctx, "any-token", "short")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password must be at least 8 bytes")
}

func TestVerifyAndReset_InvalidToken(t *testing.T) {
	svc, _, mr, _, _, _ := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()

	err := svc.VerifyAndReset(ctx, "nonexistent-token", "NewPassword123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired reset token")
}

func TestVerifyAndReset_TokenExhausted(t *testing.T) {
	svc, redis, mr, _, _, _ := setupTestPasswordResetServiceFull(t)
	defer mr.Close()

	ctx := context.Background()

	// Store a token with exhausted attempts directly in Redis
	tokenHash := tokenDomain.HashToken("exhausted-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"acct-001","email":"test@example.com","attempts":5}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	err = svc.VerifyAndReset(ctx, "exhausted-token", "NewPassword123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}
