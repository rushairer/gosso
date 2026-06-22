package service

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/cache"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// ──────────────────────────────────────────────
// mock AccountService for auth tests
// ──────────────────────────────────────────────

type testAccountService struct {
	byID         map[string]*accountDomain.Account    // key: accountID
	byUsername   map[string]*accountDomain.Account    // key: username
	passwordCred map[string]*accountDomain.Credential // key: username (populated by seedTestAccount)
}

func (m *testAccountService) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *testAccountService) FindAccountByID(_ context.Context, accountID string) (*accountDomain.Account, error) {
	if acct, ok := m.byID[accountID]; ok {
		return acct, nil
	}
	return nil, fmt.Errorf("account not found: %s", accountID)
}

func (m *testAccountService) FindAccountByUsername(_ context.Context, username string) (*accountDomain.Account, error) {
	if acct, ok := m.byUsername[username]; ok {
		return acct, nil
	}
	return nil, fmt.Errorf("account not found: %s", username)
}

func (m *testAccountService) FindByUsernameWithPasswordCredential(_ context.Context, username string) (*accountDomain.Account, *accountDomain.Credential, error) {
	acct, ok := m.byUsername[username]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", accountRepo.ErrAccountNotFound, username)
	}
	cred, ok := m.passwordCred[username]
	if !ok {
		return acct, nil, fmt.Errorf("%w: account=%s", accountRepo.ErrCredentialNotFound, acct.ID)
	}
	return acct, cred, nil
}

func (m *testAccountService) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) SoftDeleteAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) VerifyContactCredential(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) ChangePassword(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) AssignRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) RemoveRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (m *testAccountService) SuspendAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) ActivateAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *testAccountService) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *testAccountService) SetOptions(_ *accountService.AccountServiceOptions) {}

// ──────────────────────────────────────────────
// mock RoleRepository for auth tests
// ──────────────────────────────────────────────

type testRoleRepository struct {
	roles map[string][]*accountDomain.Role // key: accountID
}

func (m *testRoleRepository) CreateRole(_ context.Context, _ *sql.Tx, _ *accountDomain.Role) error {
	return fmt.Errorf("not implemented")
}

func (m *testRoleRepository) UpdateRole(_ context.Context, _ *sql.Tx, _ *accountDomain.Role) error {
	return fmt.Errorf("not implemented")
}

func (m *testRoleRepository) FindByID(_ context.Context, _ string) (*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *testRoleRepository) FindByIDTx(_ context.Context, _ *sql.Tx, _ string) (*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *testRoleRepository) FindByName(_ context.Context, _ string) (*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *testRoleRepository) FindAll(_ context.Context, _, _ int) ([]*accountDomain.Role, int, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (m *testRoleRepository) SoftDeleteRoleByID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *testRoleRepository) AssignRoleToAccount(_ context.Context, _ *sql.Tx, _, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *testRoleRepository) RemoveRoleFromAccount(_ context.Context, _ *sql.Tx, _, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *testRoleRepository) FindRolesByAccountID(_ context.Context, accountID string) ([]*accountDomain.Role, error) {
	if roles, ok := m.roles[accountID]; ok {
		return roles, nil
	}
	return nil, nil
}

func (m *testRoleRepository) SoftDeleteRolesByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

// ──────────────────────────────────────────────
// CredentialRepository with configurable FindPasswordCredential
// ──────────────────────────────────────────────

// authTestCredentialRepo extends mockCredentialRepo (defined in mfa_service_test.go)
// with a real FindPasswordCredential implementation for auth login tests.
type authTestCredentialRepo struct {
	*mockCredentialRepo
	passwordCreds  map[string]*accountDomain.Credential // key: accountID
	typeAndIDCreds map[string]*accountDomain.Credential // key: "type:identifier"
	// findByAccountAndTypeForUpdateErr, if set, causes FindByAccountAndTypeForUpdate
	// to return this error without consulting the embedded mock.
	findByAccountAndTypeForUpdateErr error
}

func (m *authTestCredentialRepo) FindPasswordCredential(_ context.Context, accountID string) (*accountDomain.Credential, error) {
	if cred, ok := m.passwordCreds[accountID]; ok {
		return cred, nil
	}
	return nil, fmt.Errorf("password credential not found for account %s", accountID)
}

func (m *authTestCredentialRepo) FindPasswordCredentialTx(ctx context.Context, _ *sql.Tx, accountID string) (*accountDomain.Credential, error) {
	return m.FindPasswordCredential(ctx, accountID)
}

func (m *authTestCredentialRepo) FindByTypeAndIdentifier(_ context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	if m.typeAndIDCreds != nil {
		key := string(credType) + ":" + identifier
		if cred, ok := m.typeAndIDCreds[key]; ok {
			return cred, nil
		}
	}
	return nil, fmt.Errorf("credential not found for %s:%s", credType, identifier)
}

// FindByAccountAndTypeForUpdate shadows the embedded mock so that tests can
// inject errors specifically in the backup-code transaction path while
// leaving FindByAccountAndType (used by VerifyTOTP) unaffected.
func (m *authTestCredentialRepo) FindByAccountAndTypeForUpdate(ctx context.Context, tx *sql.Tx, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeForUpdateErr != nil {
		return nil, m.findByAccountAndTypeForUpdateErr
	}
	return m.mockCredentialRepo.FindByAccountAndTypeForUpdate(ctx, tx, accountID, credType)
}

func (m *authTestCredentialRepo) FindByTypeAndIdentifierTx(ctx context.Context, _ *sql.Tx, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	return m.FindByTypeAndIdentifier(ctx, credType, identifier)
}

func (m *authTestCredentialRepo) FindByAccountAndTypeTx(ctx context.Context, _ *sql.Tx, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return m.FindByAccountAndType(ctx, accountID, credType)
}

// ──────────────────────────────────────────────
// Auth service test fixture
// ──────────────────────────────────────────────

type authServiceFixture struct {
	svc        *AuthService
	redis      *cache.RedisClient
	mr         interface{ Close() }
	sqlDB      *sql.DB
	sqlMock    sqlmock.Sqlmock
	accountSvc *testAccountService
	credRepo   *authTestCredentialRepo
	roleRepo   *testRoleRepository
	sessionSvc *sessionService.SessionService
	tokenSvc   *tokenService.TokenService
	logger     *zap.Logger
}

// setupTestAuthService creates a fully-wired AuthService backed by miniredis and sqlmock.
// Cleanup (miniredis close and sqlmock DB close) is automatically registered with t.Cleanup().
func setupTestAuthService(t *testing.T) *authServiceFixture {
	t.Helper()
	logger := zap.NewNop()

	// Redis via miniredis (reuse same-package helper)
	redisClient, mr := setupTestMiniredis(t)

	// SQL mock for DB transactions
	sqlDB, sqlMock, err := sqlmock.New()
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	// Register automatic cleanup so individual tests don't need manual defers.
	t.Cleanup(func() {
		mr.Close()
		_ = sqlDB.Close()
	})

	// Real TokenService backed by miniredis + in-memory RSA key
	keySvc, err := tokenService.NewKeyService("", "test-key", false, 0, logger)
	if err != nil {
		mr.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to create key service: %v", err)
	}
	blacklistSvc, err := tokenService.NewBlacklistService(redisClient, logger)
	if err != nil {
		mr.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to create blacklist service: %v", err)
	}
	tokSvc, err := tokenService.NewTokenService(
		keySvc,
		"http://localhost:8080",
		15*60*1e9,      // 15m as time.Duration
		7*24*60*60*1e9, // 7d
		redisClient,
		blacklistSvc,
		nil,
		false,
		logger,
	)
	if err != nil {
		mr.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to create token service: %v", err)
	}

	// Real SessionService backed by miniredis
	sessSvc, err := sessionService.NewSessionServiceWithConfig(redisClient, logger, sessionService.SessionConfig{
		TokenRevoker: tokSvc,
	})
	if err != nil {
		mr.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to create session service: %v", err)
	}

	// Mock services
	accountSvc := &testAccountService{
		byID:         make(map[string]*accountDomain.Account),
		byUsername:   make(map[string]*accountDomain.Account),
		passwordCred: make(map[string]*accountDomain.Credential),
	}
	credRepo := &authTestCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: make(map[string][]*accountDomain.Credential)},
		passwordCreds:      make(map[string]*accountDomain.Credential),
		typeAndIDCreds:     make(map[string]*accountDomain.Credential),
	}
	roleRepo := &testRoleRepository{roles: make(map[string][]*accountDomain.Role)}

	// MFA service — wired to sqlmock so VerifyBackupCode can open transactions.
	mfaSvc, err := NewMFAService(credRepo, sqlDB, "http://localhost:8080", logger, nil)
	if err != nil {
		t.Fatalf("NewMFAService: %v", err)
	}

	// Passkey service
	passkeySvc := NewPasskeyService(nil, nil, nil, nil, nil, logger)

	// Auth service — nil auditor (safe: AuditLog/AuditLogSync check for nil)
	svc := NewAuthService(
		sqlDB,
		accountSvc,
		sessSvc,
		tokSvc,
		credRepo,
		roleRepo,
		redisClient,
		logger,
		nil, // auditor
		mfaSvc,
		passkeySvc,
	)

	return &authServiceFixture{
		svc:        svc,
		redis:      redisClient,
		mr:         mr,
		sqlDB:      sqlDB,
		sqlMock:    sqlMock,
		accountSvc: accountSvc,
		credRepo:   credRepo,
		roleRepo:   roleRepo,
		sessionSvc: sessSvc,
		tokenSvc:   tokSvc,
		logger:     logger,
	}
}

// seedTestAccount adds a test account with a password credential to the fixture.
func (f *authServiceFixture) seedTestAccount(accountID, username, password string) {
	acct, _ := accountDomain.NewAccount(username)
	acct.ID = accountID
	uname := username
	acct.Username = &uname

	f.accountSvc.byID[accountID] = acct
	f.accountSvc.byUsername[username] = acct

	hashedPW, _ := accountDomain.HashPassword(password)
	cred := &accountDomain.Credential{
		ID:        "cred-" + accountID,
		AccountID: accountID,
		Type:      accountDomain.CredentialTypePassword,
		Value:     hashedPW,
		Verified:  true,
	}
	f.credRepo.passwordCreds[accountID] = cred
	f.accountSvc.passwordCred[username] = cred
}
