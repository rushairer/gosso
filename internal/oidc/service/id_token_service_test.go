package service

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/testutil"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// mockAccountService implements accountService.AccountService for testing
type mockAccountService struct {
	accounts map[string]*accountDomain.Account
}

func (m *mockAccountService) FindAccountByID(_ context.Context, accountID string) (*accountDomain.Account, error) {
	if a, ok := m.accounts[accountID]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("account not found: %s", accountID)
}

func (m *mockAccountService) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, nil
}
func (m *mockAccountService) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, nil
}
func (m *mockAccountService) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return nil
}
func (m *mockAccountService) SoftDeleteAccount(_ context.Context, _ string) error       { return nil }
func (m *mockAccountService) VerifyContactCredential(_ context.Context, _ string) error { return nil }
func (m *mockAccountService) ChangePassword(_ context.Context, _, _, _ string) error {
	return nil
}
func (m *mockAccountService) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockAccountService) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	return nil
}
func (m *mockAccountService) AssignRole(_ context.Context, _, _ string) error { return nil }
func (m *mockAccountService) RemoveRole(_ context.Context, _, _ string) error { return nil }
func (m *mockAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, nil
}
func (m *mockAccountService) SuspendAccount(_ context.Context, _ string) error  { return nil }
func (m *mockAccountService) ActivateAccount(_ context.Context, _ string) error { return nil }

func (m *mockAccountService) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, nil
}
func (m *mockAccountService) SetOptions(_ *accountService.AccountServiceOptions) {}

// mockCredentialRepo implements accountRepo.CredentialRepository for testing
type mockCredentialRepo struct {
	credentials             map[string][]*accountDomain.Credential // key: accountID:credType
	findByAccountAndTypeErr error
}

func (m *mockCredentialRepo) FindByAccountAndType(_ context.Context, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeErr != nil {
		return nil, m.findByAccountAndTypeErr
	}
	key := accountID + ":" + string(credType)
	if creds, ok := m.credentials[key]; ok {
		return creds, nil
	}
	return nil, nil
}

func (m *mockCredentialRepo) FindByAccountAndTypes(_ context.Context, accountID string, credTypes ...accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeErr != nil {
		return nil, m.findByAccountAndTypeErr
	}
	var result []*accountDomain.Credential
	for _, ct := range credTypes {
		key := accountID + ":" + string(ct)
		if creds, ok := m.credentials[key]; ok {
			result = append(result, creds...)
		}
	}
	return result, nil
}

func (m *mockCredentialRepo) FindByTypeAndIdentifier(_ context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	for _, creds := range m.credentials {
		for _, c := range creds {
			if c.Type == credType && c.Identifier != nil && *c.Identifier == identifier {
				return c, nil
			}
		}
	}
	return nil, accountRepo.ErrCredentialNotFound
}

func (m *mockCredentialRepo) CreateCredentials(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
	return nil
}
func (m *mockCredentialRepo) FindPasswordCredential(_ context.Context, _ string) (*accountDomain.Credential, error) {
	return nil, nil
}
func (m *mockCredentialRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	return nil
}
func (m *mockCredentialRepo) UpdateLastUsedAt(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockCredentialRepo) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockCredentialRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockCredentialRepo) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	return false, nil
}
func (m *mockCredentialRepo) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return nil, nil
}
func (m *mockCredentialRepo) FindByAccountAndTypeTx(ctx context.Context, _ *sql.Tx, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return m.FindByAccountAndType(ctx, accountID, credType)
}
func (m *mockCredentialRepo) FindByTypeAndIdentifierTx(ctx context.Context, _ *sql.Tx, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	return m.FindByTypeAndIdentifier(ctx, credType, identifier)
}

func setupTestIDTokenService(t *testing.T) (*IDTokenService, func()) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)
	cleanup := mr.Close

	blacklist, errBS := tokenService.NewBlacklistService(redisClient, logger)
	require.NoError(t, errBS)
	keySvc, err := tokenService.NewKeyService("", "", false, 0, logger)
	require.NoError(t, err)
	tokenSvc, err := tokenService.NewTokenService(
		keySvc,
		"http://localhost:8080",
		15*time.Minute,
		7*24*time.Hour,
		redisClient,
		blacklist,
		nil,
		false,
		logger,
	)
	require.NoError(t, err)

	username := "testuser"
	avatarURL := "https://example.com/avatar.png"
	accountSvc := &mockAccountService{
		accounts: map[string]*accountDomain.Account{
			"account-001": {
				ID:          "account-001",
				Username:    &username,
				DisplayName: "Test User",
				AvatarURL:   &avatarURL,
				Status:      accountDomain.AccountStatusActive,
				Locale:      "zh-CN",
				Timezone:    "Asia/Shanghai",
			},
		},
	}

	credRepo := &mockCredentialRepo{
		credentials: map[string][]*accountDomain.Credential{
			"account-001:email": {
				{
					ID:         "cred-email-001",
					AccountID:  "account-001",
					Type:       accountDomain.CredentialTypeEmail,
					Identifier: strPtr("test@example.com"),
					Verified:   true,
				},
			},
			"account-001:phone": {
				{
					ID:         "cred-phone-001",
					AccountID:  "account-001",
					Type:       accountDomain.CredentialTypePhone,
					Identifier: strPtr("+8613800138000"),
					Verified:   true,
				},
			},
		},
	}

	svc := NewIDTokenService(tokenSvc, "http://localhost:8080", accountSvc, credRepo, 0, logger)
	return svc, cleanup
}

func strPtr(s string) *string { return &s }

func TestGenerateIDToken_OpenID(t *testing.T) {
	svc, cleanup := setupTestIDTokenService(t)
	defer cleanup()

	ctx := context.Background()

	tokenString, err := svc.GenerateIDToken(ctx, "account-001", "client-001", []string{"openid"}, "test-nonce", time.Now(), "", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "account-001", claims["sub"])
	assert.Equal(t, "http://localhost:8080", claims["iss"])
	assert.Equal(t, "test-nonce", claims["nonce"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["auth_time"])

	// openid only — no profile/email/phone claims
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["email"])
}

func TestGenerateIDToken_ProfileScope(t *testing.T) {
	svc, cleanup := setupTestIDTokenService(t)
	defer cleanup()

	ctx := context.Background()

	tokenString, err := svc.GenerateIDToken(ctx, "account-001", "client-001", []string{"openid", "profile"}, "", time.Now(), "", nil)
	require.NoError(t, err)

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "Test User", claims["name"])
	assert.Equal(t, "testuser", claims["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.png", claims["picture"])
	assert.Equal(t, "zh-CN", claims["locale"])
}

func TestGenerateIDToken_EmailScope(t *testing.T) {
	svc, cleanup := setupTestIDTokenService(t)
	defer cleanup()

	ctx := context.Background()

	tokenString, err := svc.GenerateIDToken(ctx, "account-001", "client-001", []string{"openid", "email"}, "", time.Now(), "", nil)
	require.NoError(t, err)

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "test@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
}

func TestGenerateIDToken_PhoneScope(t *testing.T) {
	svc, cleanup := setupTestIDTokenService(t)
	defer cleanup()

	ctx := context.Background()

	tokenString, err := svc.GenerateIDToken(ctx, "account-001", "client-001", []string{"openid", "phone"}, "", time.Now(), "", nil)
	require.NoError(t, err)

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "+8613800138000", claims["phone_number"])
	assert.Equal(t, true, claims["phone_number_verified"])
}

func TestGenerateIDToken_RS256(t *testing.T) {
	svc, cleanup := setupTestIDTokenService(t)
	defer cleanup()

	ctx := context.Background()

	tokenString, err := svc.GenerateIDToken(ctx, "account-001", "client-001", []string{"openid"}, "", time.Now(), "", nil)
	require.NoError(t, err)

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	assert.Equal(t, "RS256", token.Header["alg"])
	assert.NotEmpty(t, token.Header["kid"])
}
