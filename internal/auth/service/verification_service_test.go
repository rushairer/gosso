package service

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/testutil"
)

// stubEmailService captures the code instead of sending email
type stubEmailService struct {
	sentCodes []string
}

func (s *stubEmailService) SendVerificationCode(_ context.Context, _, code string) error {
	s.sentCodes = append(s.sentCodes, code)
	return nil
}

// stubSMSService is a no-op SMS service for testing
type stubSMSService struct{}

func (s *stubSMSService) SendVerificationCode(_ context.Context, _, _ string) error {
	return nil
}

// setupTestVerificationServiceBase creates a VerificationService backed by miniredis
// WITHOUT checking for cjson support. Use this for tests that only need
// plain Redis commands (SET/GET/EXISTS) — e.g. SendCode and its cooldown logic.
func setupTestVerificationServiceBase(t *testing.T) (*VerificationService, *cache.RedisClient, func(), *stubEmailService) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)
	cleanup := mr.Close

	emailSvc := &stubEmailService{}
	smsSvc := &stubSMSService{}
	svc := NewVerificationService(redisClient, emailSvc, smsSvc, nil, logger)

	return svc, redisClient, cleanup, emailSvc
}

// setupTestVerificationServiceCJSON is like setupTestVerificationServiceBase but skips
// the test when the Redis instance does not support the Lua cjson module.
// Required for VerifyCode and VerifyCodeForAccount which use cjson in their Lua scripts.
func setupTestVerificationServiceCJSON(t *testing.T) (*VerificationService, *cache.RedisClient, func(), *stubEmailService) {
	t.Helper()
	svc, redisClient, cleanup, emailSvc := setupTestVerificationServiceBase(t)
	testutil.SkipIfNoCJSON(t, redisClient)
	return svc, redisClient, cleanup, emailSvc
}

func TestVerifyCode_Success(t *testing.T) {
	svc, _, cleanup, emailSvc := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "test@example.com", "account-001")
	require.NoError(t, err)
	require.Len(t, emailSvc.sentCodes, 1)
	code := emailSvc.sentCodes[0]

	// Verify
	accountID, err := svc.VerifyCode(ctx, "email", "test@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, "account-001", accountID)
}

func TestVerifyCode_Wrong(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "wrong@example.com", "account-002")
	require.NoError(t, err)

	// Incorrect verification code
	_, err = svc.VerifyCode(ctx, "email", "wrong@example.com", "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid verification code")
}

func TestVerifyCode_Exhausted(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "exhaust@example.com", "account-003")
	require.NoError(t, err)

	// 5 incorrect attempts
	for i := 0; i < 5; i++ {
		_, _ = svc.VerifyCode(ctx, "email", "exhaust@example.com", "wrong")
	}

	// 6th attempt should return exhausted
	_, err = svc.VerifyCode(ctx, "email", "exhaust@example.com", "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

func TestVerifyCode_Expired(t *testing.T) {
	svc, redis, cleanup, emailSvc := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "expired@example.com", "account-004")
	require.NoError(t, err)

	// Manually delete key to simulate expiration
	codeKey := svc.buildCodeKey("email", "expired@example.com")
	_ = redis.Del(ctx, codeKey)

	// Verify
	_, err = svc.VerifyCode(ctx, "email", "expired@example.com", emailSvc.sentCodes[0])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired or not found")
}

func TestSendCode_Cooldown(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationServiceBase(t)
	defer cleanup()

	ctx := context.Background()

	// First send
	err := svc.SendCode(ctx, "email", "cooldown@example.com", "account-005")
	require.NoError(t, err)

	// Second send should trigger cooldown
	err = svc.SendCode(ctx, "email", "cooldown@example.com", "account-005")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please wait")
}

func TestVerifyCode_CodeReuse(t *testing.T) {
	svc, _, cleanup, emailSvc := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	// Send
	err := svc.SendCode(ctx, "email", "reuse@example.com", "account-006")
	require.NoError(t, err)
	code := emailSvc.sentCodes[0]

	// 1st verification succeeds
	accountID, err := svc.VerifyCode(ctx, "email", "reuse@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, "account-006", accountID)

	// 2nd verification should fail (code has been deleted)
	_, err = svc.VerifyCode(ctx, "email", "reuse@example.com", code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired or not found")
}


// ──────────────────────────────────────────────
// Unsupported type test
// ──────────────────────────────────────────────

func TestSendCode_UnsupportedType(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationServiceBase(t)
	defer cleanup()

	ctx := context.Background()
	err := svc.SendCode(ctx, "sms_unsupported", "+1234567890", "account-xxx")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

// ──────────────────────────────────────────────
// VerifyCodeForAccount tests
// ──────────────────────────────────────────────

func TestVerifyCodeForAccount_Success(t *testing.T) {
	svc, _, cleanup, emailSvc := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	err := svc.SendCode(ctx, "email", "vca-ok@example.com", "acct-vca")
	require.NoError(t, err)
	require.Len(t, emailSvc.sentCodes, 1)
	code := emailSvc.sentCodes[0]

	err = svc.VerifyCodeForAccount(ctx, "email", "vca-ok@example.com", code, "acct-vca")
	assert.NoError(t, err)
}

func TestVerifyCodeForAccount_WrongAccount(t *testing.T) {
	svc, _, cleanup, emailSvc := setupTestVerificationServiceCJSON(t)
	defer cleanup()

	ctx := context.Background()

	err := svc.SendCode(ctx, "email", "vca-wrong@example.com", "acct-real")
	require.NoError(t, err)
	require.Len(t, emailSvc.sentCodes, 1)
	code := emailSvc.sentCodes[0]

	err = svc.VerifyCodeForAccount(ctx, "email", "vca-wrong@example.com", code, "acct-impostor")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong to this account")
}

// ──────────────────────────────────────────────
// ValidateCredentialOwnership tests
// ──────────────────────────────────────────────

func TestValidateCredentialOwnership_Success(t *testing.T) {
	_, _, cleanup, _ := setupTestVerificationServiceBase(t)
	defer cleanup()

	ctx := context.Background()

	mockRepo := &mockCredRepoForVerification{
		creds: []*accountDomain.Credential{
			{ID: "c1", AccountID: "acct-own", Type: accountDomain.CredentialTypeEmail, Identifier: strPtr("owner@example.com")},
		},
	}

	svc := NewVerificationService(nil, nil, nil, mockRepo, nil)
	err := svc.ValidateCredentialOwnership(ctx, "acct-own", "email", "owner@example.com")
	assert.NoError(t, err)
}

func TestValidateCredentialOwnership_NotOwned(t *testing.T) {
	mockRepo := &mockCredRepoForVerification{
		creds: []*accountDomain.Credential{
			{ID: "c1", AccountID: "acct-own", Type: accountDomain.CredentialTypeEmail, Identifier: strPtr("owner@example.com")},
		},
	}

	svc := NewVerificationService(nil, nil, nil, mockRepo, nil)
	err := svc.ValidateCredentialOwnership(context.Background(), "acct-own", "email", "other@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not associated with this account")
}

func TestValidateCredentialOwnership_RepoError(t *testing.T) {
	mockRepo := &mockCredRepoForVerification{
		err: fmt.Errorf("database down"),
	}

	svc := NewVerificationService(nil, nil, nil, mockRepo, nil)
	err := svc.ValidateCredentialOwnership(context.Background(), "acct-x", "email", "x@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lookup credentials")
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

type mockCredRepoForVerification struct {
	creds []*accountDomain.Credential
	err   error
}

func (m *mockCredRepoForVerification) CreateCredentials(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) FindByAccountAndType(_ context.Context, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.creds, nil
}

func (m *mockCredRepoForVerification) FindByAccountAndTypes(_ context.Context, _ string, _ ...accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.creds, nil
}

func (m *mockCredRepoForVerification) FindByTypeAndIdentifier(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) FindPasswordCredential(_ context.Context, _ string) (*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) UpdateLastUsedAt(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func (m *mockCredRepoForVerification) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockCredRepoForVerification) FindByAccountAndTypeTx(ctx context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return m.FindByAccountAndType(ctx, "", "")
}

func (m *mockCredRepoForVerification) FindByTypeAndIdentifierTx(ctx context.Context, _ *sql.Tx, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
	return m.FindByTypeAndIdentifier(ctx, "", "")
}

func strPtr(s string) *string { return &s }

// ──────────────────────────────────────────────
// Pure helper tests (no Redis required)
// ──────────────────────────────────────────────

func TestGenerateNumericCode(t *testing.T) {
	for _, length := range []int{4, 6, 8} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			code, err := generateNumericCode(length)
			require.NoError(t, err)
			assert.Len(t, code, length)
			for _, c := range code {
				assert.True(t, c >= '0' && c <= '9', "unexpected char: %c", c)
			}
		})
	}
}

func TestGenerateNumericCode_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generateNumericCode(6)
		require.NoError(t, err)
		seen[code] = true
	}
	assert.Greater(t, len(seen), 90)
}

func TestBuildCodeKey(t *testing.T) {
	svc := NewVerificationService(nil, nil, nil, nil, nil)
	got := svc.buildCodeKey("email", "user@example.com")
	assert.Equal(t, "verify:code:email:user@example.com", got)
}

func TestBuildCooldownKey(t *testing.T) {
	svc := NewVerificationService(nil, nil, nil, nil, nil)
	got := svc.buildCooldownKey("phone", "+1234567890")
	assert.Equal(t, "verify:cooldown:phone:+1234567890", got)
}

func TestMaskIdentifier_DelegatesToUtility(t *testing.T) {
	result := maskIdentifier("email", "test@example.com")
	assert.NotEmpty(t, result)
}
