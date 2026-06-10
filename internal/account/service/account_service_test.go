package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
)

// stubSessionRevoker implements SessionRevoker for testing.
type stubSessionRevoker struct{}

func (s *stubSessionRevoker) RevokeAllForAccount(_ context.Context, _ string) error { return nil }

// stubOAuth2ClientDeleter implements OAuth2ClientDeleter for testing.
type stubOAuth2ClientDeleter struct{}

func (s *stubOAuth2ClientDeleter) SoftDeleteOAuth2ClientsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

// TestFindAccountByID tests finding an account by ID
func TestFindAccountByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	account, err := accountService.FindAccountByID(context.Background(), "account-001")

	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, "account-001", account.ID)
	assert.Equal(t, "testuser", *account.Username)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestFindAccountByID_NotFound tests that finding a nonexistent account returns an error
func TestFindAccountByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	account, err := accountService.FindAccountByID(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, account)
	assert.ErrorIs(t, err, repository.ErrAccountNotFound)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestFindAccountByUsername tests finding an account by username
func TestFindAccountByUsername(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE username").
		WithArgs("testuser").
		WillReturnRows(accountRows)

	account, err := accountService.FindAccountByUsername(context.Background(), "testuser")

	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, "account-001", account.ID)
	assert.Equal(t, "testuser", *account.Username)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestListAccounts tests listing accounts
func TestListAccounts(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WillReturnRows(accountRows)

	accounts, total, err := accountService.ListAccounts(context.Background(), 1, 20, "")

	assert.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, accounts, 1)
	assert.Equal(t, "account-001", accounts[0].ID)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestListAccounts_Empty tests listing accounts when none exist
func TestListAccounts_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	accounts, total, err := accountService.ListAccounts(context.Background(), 1, 20, "")

	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Len(t, accounts, 0)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetAccountRoles tests getting roles for an account
func TestGetAccountRoles(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	roleRows := sqlmock.NewRows([]string{
		"id", "name", "description", "permissions", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"role-001", "admin", "Administrator", []byte(`["*"]`), []byte("{}"), now, now, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM roles").
		WithArgs("account-001").
		WillReturnRows(roleRows)

	roles, err := accountService.GetAccountRoles(context.Background(), "account-001")

	assert.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestActivateAccount tests activating a suspended account
func TestActivateAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE accounts SET status").
		WithArgs(sqlmock.AnyArg(), "test-account-id", "active", "suspended").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.ActivateAccount(context.Background(), "test-account-id")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAssignRole tests assigning a role to an account
func TestAssignRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	// Mock role FindByID — role exists and is not deleted
	roleRows := sqlmock.NewRows([]string{
		"id", "name", "description", "permissions", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"role-001", "admin", "Administrator", []byte(`["*"]`), []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM roles WHERE id").
		WithArgs("role-001").
		WillReturnRows(roleRows)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO account_roles").
		WithArgs("account-001", "role-001").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = accountService.AssignRole(context.Background(), "account-001", "role-001")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRemoveRole tests removing a role from an account
func TestRemoveRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WithArgs(sqlmock.AnyArg(), "account-001", "role-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.RemoveRole(context.Background(), "account-001", "role-001")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRemoveRole_NotFound tests removing a role that is not assigned
func TestRemoveRole_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WithArgs(sqlmock.AnyArg(), "account-001", "nonexistent-role").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = accountService.RemoveRole(context.Background(), "account-001", "nonexistent-role")

	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestWithSessionRevoker_NilPanics tests that setting a nil session revoker panics
func TestWithSessionRevoker_NilPanics(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	assert.Panics(t, func() {
		NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, WithSessionRevoker(nil))
	})
}

// TestWithOAuth2ClientDeleter_NilPanics tests that setting a nil OAuth2 client deleter panics
func TestWithOAuth2ClientDeleter_NilPanics(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	assert.Panics(t, func() {
		NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, WithOAuth2ClientDeleter(nil))
	})
}

// TestRegisterAccount tests account registration
func TestRegisterAccount(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Create repositories and services
	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	// Set mock expectations (in order of execution)

	// 1. Expect querying whether email exists (executed outside transaction)
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnError(sql.ErrNoRows)

	// 2. Begin transaction
	mock.ExpectBegin()

	// 3. Expect inserting account
	mock.ExpectExec("INSERT INTO accounts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 4. Expect batch inserting credentials (password + email, 2 in total)
	// CreateCredentials uses a loop insertion, so 2 ExpectExecs are required
	mock.ExpectExec("INSERT INTO account_credentials").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectExec("INSERT INTO account_credentials").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 5. Commit transaction
	mock.ExpectCommit()

	// Execute registration
	req := &RegisterAccountRequest{
		Username:    "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
		Password:    "TestPassword123!",
		Locale:      "en",
		Timezone:    "UTC",
	}

	account, err := accountService.RegisterAccount(context.Background(), req)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.NotNil(t, account.Username)
	assert.Equal(t, "testuser", *account.Username)
	assert.Equal(t, "Test User", account.DisplayName)
	assert.Equal(t, domain.AccountStatusActive, account.Status)

	// Verify all expectations are met
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRegisterAccount_DuplicateEmail tests duplicate email registration
func TestRegisterAccount_DuplicateEmail(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	// Set mock: email already exists (queried outside transaction)
	// Note: requires all columns to be returned to match Scan of FindByTypeAndIdentifier
	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier",
		"credential_value", "verified", "primary_credential", "metadata",
		"created_at", "verified_at", "last_used_at", "deleted_at",
	}).AddRow(
		"existing-id", "existing-account-id", domain.CredentialTypeEmail, "test@example.com",
		"", true, true, []byte("{}"),
		time.Now(), nil, nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnRows(rows)

	// Note: after detecting duplicate email, transaction won't begin, so ExpectBegin is not needed

	// Execute registration
	req := &RegisterAccountRequest{
		Username:    "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
		Password:    "TestPassword123!",
	}

	account, err := accountService.RegisterAccount(context.Background(), req)

	// Print detailed error message
	if err != nil {
		t.Logf("Error message: %v", err)
	}

	// Verify result: should return error
	assert.Error(t, err)
	assert.Nil(t, account)
	assert.ErrorIs(t, err, ErrEmailAlreadyRegistered)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestChangePassword tests changing password
func TestChangePassword(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)
	impl := accountService.(*accountServiceImpl)
	impl.setSessionRevoker(&stubSessionRevoker{})
	impl.setOAuth2ClientDeleter(&stubOAuth2ClientDeleter{})

	accountID := "test-account-id"
	oldPassword := "OldPassword123!"
	newPassword := "NewPassword456!"

	// Generate a real argon2id hash for the old password
	oldHash, err := domain.HashPassword(oldPassword)
	require.NoError(t, err)

	// Mock FindByID for requireActiveAccount
	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier", "credential_value",
		"verified", "primary_credential", "metadata", "created_at", "verified_at", "last_used_at", "deleted_at",
	}).AddRow(
		"cred-id", accountID, domain.CredentialTypePassword, "test@example.com", oldHash,
		true, true, []byte("{}"), time.Now(), nil, nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePassword).
		WillReturnRows(rows)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.ChangePassword(context.Background(), accountID, oldPassword, newPassword)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSoftDeleteAccount tests soft deleting account
func TestSoftDeleteAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)
	impl := accountService.(*accountServiceImpl)
	impl.setSessionRevoker(&stubSessionRevoker{})
	impl.setOAuth2ClientDeleter(&stubOAuth2ClientDeleter{})

	accountID := "test-account-id"

	// Set mock expectations

	// Expect FindByID for idempotency check (account not deleted) — now inside transaction
	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	mock.ExpectBegin()

	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	// Expect soft deleting credentials
	mock.ExpectExec("UPDATE account_credentials SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 2))

	// Expect soft deleting third-party identities
	mock.ExpectExec("UPDATE federated_identities SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Expect soft deleting role associations
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 3))

	// Expect soft deleting OAuth2 clients (handled by stubOAuth2ClientDeleter, no SQL expectation)

	// Expect soft deleting account
	mock.ExpectExec("UPDATE accounts SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	// Execute deletion
	err = accountService.SoftDeleteAccount(context.Background(), accountID)

	// Verify results
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSuspendAccount tests suspending an account
func TestSuspendAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)
	impl := accountService.(*accountServiceImpl)
	impl.setSessionRevoker(&stubSessionRevoker{})
	impl.setOAuth2ClientDeleter(&stubOAuth2ClientDeleter{})

	accountID := "test-account-id"

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE accounts SET status").
		WithArgs(sqlmock.AnyArg(), accountID, "suspended", "active").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.SuspendAccount(context.Background(), accountID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSuspendAccount_NilSessionRevoker tests that SuspendAccount fails fast when session revoker is not configured
func TestSuspendAccount_NilSessionRevoker(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	err = accountService.SuspendAccount(context.Background(), "test-account-id")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SessionRevoker not configured")
}

// TestUpdateAccount tests updating account information
func TestUpdateAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	username := "updateduser"
	account := &domain.Account{
		ID:          "account-001",
		Username:    &username,
		DisplayName: "Updated User",
		Status:      domain.AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    map[string]any{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE accounts").
		WithArgs(
			account.Username,
			account.DisplayName,
			account.AvatarURL,
			account.Status,
			account.Locale,
			account.Timezone,
			sqlmock.AnyArg(), // metadata JSON
			sqlmock.AnyArg(), // updated_at
			account.ID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.UpdateAccount(context.Background(), account)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUpdateAccount_NotFound tests updating a nonexistent account
func TestUpdateAccount_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	now := time.Now()
	username := "ghost"
	account := &domain.Account{
		ID:          "nonexistent",
		Username:    &username,
		DisplayName: "Ghost",
		Status:      domain.AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    map[string]any{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE accounts").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = accountService.UpdateAccount(context.Background(), account)

	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestVerifyCredential_Email tests verifying an email credential
func TestVerifyCredential_Email(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-001"
	now := time.Now()

	// FindByAccountAndType for email — returns one unverified credential
	emailRows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier",
		"credential_value", "verified", "primary_credential", "metadata",
		"created_at", "verified_at", "last_used_at", "deleted_at",
	}).AddRow(
		"cred-email-001", accountID, domain.CredentialTypeEmail, "user@example.com",
		"", false, true, []byte("{}"),
		now, nil, nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypeEmail).
		WillReturnRows(emailRows)

	// UpdateCredential in transaction
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.VerifyCredential(context.Background(), accountID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestVerifyCredential_PhoneFallback tests that VerifyCredential falls back to phone when no email credential exists
func TestVerifyCredential_PhoneFallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-001"
	now := time.Now()

	// FindByAccountAndType for email — not found
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypeEmail).
		WillReturnError(repository.ErrCredentialNotFound)

	// FindByAccountAndType for phone — returns one unverified credential
	phoneRows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier",
		"credential_value", "verified", "primary_credential", "metadata",
		"created_at", "verified_at", "last_used_at", "deleted_at",
	}).AddRow(
		"cred-phone-001", accountID, domain.CredentialTypePhone, "+1234567890",
		"", false, true, []byte("{}"),
		now, nil, nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePhone).
		WillReturnRows(phoneRows)

	// UpdateCredential in transaction
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.VerifyCredential(context.Background(), accountID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestVerifyCredential_NoCredentialFound tests VerifyCredential when neither email nor phone exists
func TestVerifyCredential_NoCredentialFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-no-creds"

	// Email not found
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypeEmail).
		WillReturnError(repository.ErrCredentialNotFound)

	// Phone not found
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePhone).
		WillReturnError(repository.ErrCredentialNotFound)

	err = accountService.VerifyCredential(context.Background(), accountID)

	assert.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrCredentialNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestBindFederatedIdentity tests binding a third-party identity
func TestBindFederatedIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-001"

	// Mock FindByID for requireActiveAccount
	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	mock.ExpectBegin()

	// FindByProvider — not found (no existing binding)
	mock.ExpectQuery("SELECT (.+) FROM federated_identities WHERE provider").
		WithArgs(string(domain.ProviderGoogle), "google-user-123").
		WillReturnError(repository.ErrFederatedIdentityNotFound)

	// CreateFederatedIdentity
	mock.ExpectExec("INSERT INTO federated_identities").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	profile := map[string]interface{}{"name": "Test User", "email": "test@gmail.com"}
	err = accountService.BindFederatedIdentity(context.Background(), accountID, domain.ProviderGoogle, "google-user-123", profile)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestBindFederatedIdentity_AlreadyBound tests binding when identity already belongs to another account
func TestBindFederatedIdentity_AlreadyBound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-001"
	now := time.Now()

	// Mock FindByID for requireActiveAccount
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	mock.ExpectBegin()

	// FindByProvider — found existing binding
	existingRows := sqlmock.NewRows([]string{
		"id", "account_id", "provider", "provider_user_id", "profile", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"fi-001", "other-account", domain.ProviderGoogle, "google-user-123",
		[]byte("{}"), now, now, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM federated_identities WHERE provider").
		WithArgs(string(domain.ProviderGoogle), "google-user-123").
		WillReturnRows(existingRows)

	mock.ExpectRollback()

	profile := map[string]interface{}{"name": "Test User"}
	err = accountService.BindFederatedIdentity(context.Background(), accountID, domain.ProviderGoogle, "google-user-123", profile)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFederatedIdentityAlreadyBound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUnbindFederatedIdentity tests unbinding a third-party identity
func TestUnbindFederatedIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-001"
	identityID := "fi-001"

	// Mock FindByID for requireActiveAccount
	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE federated_identities SET deleted_at").
		WithArgs(sqlmock.AnyArg(), identityID, accountID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.UnbindFederatedIdentity(context.Background(), accountID, identityID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUnbindFederatedIdentity_NotFound tests unbinding a nonexistent identity
func TestUnbindFederatedIdentity_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	accountID := "account-001"
	identityID := "nonexistent"

	// Mock FindByID for requireActiveAccount
	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE federated_identities SET deleted_at").
		WithArgs(sqlmock.AnyArg(), identityID, accountID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = accountService.UnbindFederatedIdentity(context.Background(), accountID, identityID)

	assert.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrFederatedIdentityNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestBindSessionRevoker tests late-binding session revoker
func TestBindSessionRevoker(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	err = BindSessionRevoker(accountService, &stubSessionRevoker{})
	assert.NoError(t, err)

	// Verify it was bound by calling a function that checks for it
	// SuspendAccount requires session revoker
	impl := accountService.(*accountServiceImpl)
	assert.NotNil(t, impl.sessionRevoker)
}

// TestBindSessionRevoker_InvalidType tests binding with wrong type
func TestBindSessionRevoker_InvalidType(t *testing.T) {
	// Create a minimal implementation that satisfies AccountService but is not *accountServiceImpl
	err := BindSessionRevoker(&fakeAccountService{}, &stubSessionRevoker{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not *accountServiceImpl")
}

// TestBindOAuth2ClientDeleter tests late-binding OAuth2 client deleter
func TestBindOAuth2ClientDeleter(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil)

	err = BindOAuth2ClientDeleter(accountService, &stubOAuth2ClientDeleter{})
	assert.NoError(t, err)

	impl := accountService.(*accountServiceImpl)
	assert.NotNil(t, impl.oauth2ClientDeleter)
}

// TestBindOAuth2ClientDeleter_InvalidType tests binding with wrong type
func TestBindOAuth2ClientDeleter_InvalidType(t *testing.T) {
	err := BindOAuth2ClientDeleter(&fakeAccountService{}, &stubOAuth2ClientDeleter{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not *accountServiceImpl")
}

// fakeAccountService is a non-pointer-type AccountService used to test late-bind type assertions.
type fakeAccountService struct{}

func (f *fakeAccountService) RegisterAccount(_ context.Context, _ *RegisterAccountRequest) (*domain.Account, error) {
	return nil, nil
}
func (f *fakeAccountService) FindAccountByID(_ context.Context, _ string) (*domain.Account, error) {
	return nil, nil
}
func (f *fakeAccountService) FindAccountByUsername(_ context.Context, _ string) (*domain.Account, error) {
	return nil, nil
}
func (f *fakeAccountService) UpdateAccount(_ context.Context, _ *domain.Account) error { return nil }
func (f *fakeAccountService) SoftDeleteAccount(_ context.Context, _ string) error      { return nil }
func (f *fakeAccountService) VerifyCredential(_ context.Context, _ string) error       { return nil }
func (f *fakeAccountService) ChangePassword(_ context.Context, _, _, _ string) error   { return nil }
func (f *fakeAccountService) BindFederatedIdentity(_ context.Context, _ string, _ domain.Provider, _ string, _ map[string]interface{}) error {
	return nil
}
func (f *fakeAccountService) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	return nil
}
func (f *fakeAccountService) AssignRole(_ context.Context, _, _ string) error { return nil }
func (f *fakeAccountService) RemoveRole(_ context.Context, _, _ string) error { return nil }
func (f *fakeAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*domain.Account, int, error) {
	return nil, 0, nil
}
func (f *fakeAccountService) SuspendAccount(_ context.Context, _ string) error  { return nil }
func (f *fakeAccountService) ActivateAccount(_ context.Context, _ string) error { return nil }
func (f *fakeAccountService) GetAccountRoles(_ context.Context, _ string) ([]*domain.Role, error) {
	return nil, nil
}
