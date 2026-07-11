package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	accounts, total, err := accountService.ListAccounts(context.Background(), 1, 20, "")

	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Len(t, accounts, 0)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListAccountSummaries(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "display_name", "avatar_url", "status",
			"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
		}).AddRow(
			"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
			"en", "UTC", []byte("{}"), now, now, nil,
		))
	mock.ExpectQuery("SELECT ar.account_id, r.id").
		WithArgs(`{"account-001"}`).
		WillReturnRows(sqlmock.NewRows([]string{
			"account_id", "id", "name", "description", "permissions", "metadata",
			"created_at", "updated_at", "deleted_at",
		}).AddRow(
			"account-001", "role-001", "support", "Support", []byte(`["account:read"]`),
			[]byte("{}"), now, now, nil,
		))

	summaries, total, err := accountService.ListAccountSummaries(context.Background(), 1, 20, "")

	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, summaries, 1)
	assert.Equal(t, "account-001", summaries[0].ID)
	require.Len(t, summaries[0].Roles, 1)
	assert.Equal(t, "support", summaries[0].Roles[0].Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListAccountSummaries_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	summaries, total, err := accountService.ListAccountSummaries(context.Background(), 1, 20, "")

	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, summaries)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListAccountSummaries_RoleQueryFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT (.+) FROM accounts").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "display_name", "avatar_url", "status",
			"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
		}).AddRow(
			"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
			"en", "UTC", []byte("{}"), now, now, nil,
		))
	queryErr := errors.New("role query failed")
	mock.ExpectQuery("SELECT ar.account_id, r.id").
		WithArgs(`{"account-001"}`).
		WillReturnError(queryErr)

	summaries, total, err := accountService.ListAccountSummaries(context.Background(), 1, 20, "")

	assert.ErrorIs(t, err, queryErr)
	assert.Nil(t, summaries)
	assert.Zero(t, total)
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	// Role lookup and assignment now both run inside the same transaction
	mock.ExpectBegin()

	// Account activity check runs inside the transaction (TOCTOU-safe)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	// Mock role FindByIDTx — role exists and is not deleted (inside transaction)
	roleRows := sqlmock.NewRows([]string{
		"id", "name", "description", "permissions", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"role-001", "admin", "Administrator", []byte(`["*"]`), []byte("{}"), now, now, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM roles WHERE id").
		WithArgs("role-001").
		WillReturnRows(roleRows)

	mock.ExpectExec("INSERT INTO account_roles").
		WithArgs("account-001", "role-001", sqlmock.AnyArg()).
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectBegin()

	// Account activity check runs inside the transaction (TOCTOU-safe)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)
	mock.ExpectBegin()

	// Account activity check runs inside the transaction (TOCTOU-safe)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WithArgs(sqlmock.AnyArg(), "account-001", "nonexistent-role").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = accountService.RemoveRole(context.Background(), "account-001", "nonexistent-role")

	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetOptions_NilNoOp tests that setting nil options does not panic
func TestSetOptions_NilNoOp(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.RoleRepository(nil)

	svc := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	assert.NotPanics(t, func() {
		svc.SetOptions(nil)
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	// Set mock expectations (in order of execution)

	// 1. Begin transaction
	mock.ExpectBegin()

	// 2. Expect querying whether email exists (executed inside transaction)
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnError(sql.ErrNoRows)

	// 3. Expect inserting account
	mock.ExpectExec("INSERT INTO accounts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 4. Expect batch inserting credentials (password + email in single INSERT)
	mock.ExpectExec("INSERT INTO account_credentials").
		WillReturnResult(sqlmock.NewResult(1, 2))

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	// Set mock: email already exists (queried inside transaction)
	// Note: requires all columns to be returned to match Scan of FindByTypeAndIdentifierTx
	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier",
		"credential_value", "verified", "primary_credential", "metadata",
		"created_at", "updated_at", "verified_at", "last_used_at",
	}).AddRow(
		"existing-id", "existing-account-id", domain.CredentialTypeEmail, "test@example.com",
		"", true, true, []byte("{}"),
		time.Now(), time.Now(), nil, nil,
	)

	// Begin transaction (now the uniqueness check happens inside the transaction)
	mock.ExpectBegin()

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnRows(rows)

	// Rollback due to ErrEmailAlreadyRegistered
	mock.ExpectRollback()

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	accountService.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}, OAuth2ClientDeleter: &stubOAuth2ClientDeleter{}})

	accountID := "test-account-id"
	oldPassword := "OldPassword123!"
	newPassword := "NewPassword456!"

	// Generate a real argon2id hash for the old password
	oldHash, err := domain.HashPassword(oldPassword)
	require.NoError(t, err)

	// All DB operations now happen inside a single transaction
	mock.ExpectBegin()

	// Mock FindByIDTx for account active check inside transaction
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

	// Mock FindByAccountAndTypeForUpdate for password credential lookup
	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier", "credential_value",
		"verified", "primary_credential", "metadata", "created_at", "updated_at",
		"verified_at", "last_used_at",
	}).AddRow(
		"cred-id", accountID, domain.CredentialTypePassword, "test@example.com", oldHash,
		true, true, []byte("{}"), time.Now(), time.Now(), nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePassword).
		WillReturnRows(rows)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	accountService.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}, OAuth2ClientDeleter: &stubOAuth2ClientDeleter{}})

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
		WithArgs(sqlmock.AnyArg(), string(domain.AccountStatusDeleted), accountID).
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	accountService.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}, OAuth2ClientDeleter: &stubOAuth2ClientDeleter{}})

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	updatedAt := now.Add(-1 * time.Hour)
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
		UpdatedAt:   updatedAt,
	}

	mock.ExpectBegin()

	// FindByIDTx — returns the current account (re-read inside transaction)
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		account.ID, account.Username, account.DisplayName, account.AvatarURL, string(account.Status),
		account.Locale, account.Timezone, []byte("{}"), account.CreatedAt, updatedAt, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(account.ID).
		WillReturnRows(accountRows)

	// UpdateAccount with optimistic locking (expectedUpdatedAt = updatedAt)
	mock.ExpectExec("UPDATE accounts").
		WithArgs(
			account.Username,
			account.DisplayName,
			account.AvatarURL,
			account.Status,
			account.Locale,
			account.Timezone,
			sqlmock.AnyArg(), // metadata JSON
			sqlmock.AnyArg(), // new updated_at (time.Now())
			account.ID,
			updatedAt, // expectedUpdatedAt for optimistic lock
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

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

	// FindByIDTx — returns ErrAccountNotFound (account does not exist)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(account.ID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = accountService.UpdateAccount(context.Background(), account)

	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestVerifyContactCredential_Email tests verifying an email credential
func TestVerifyContactCredential_Email(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-001"
	now := time.Now()

	// All operations run inside a single transaction (RunInTransaction)
	mock.ExpectBegin()

	// Mock FindByIDTx for requireActiveAccount (inside transaction)
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

	// FindByAccountAndTypeForUpdate for email — returns one unverified credential
	emailRows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier",
		"credential_value", "verified", "primary_credential", "metadata",
		"created_at", "updated_at", "verified_at", "last_used_at",
	}).AddRow(
		"cred-email-001", accountID, domain.CredentialTypeEmail, "user@example.com",
		"", false, true, []byte("{}"),
		now, now, nil, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypeEmail).
		WillReturnRows(emailRows)

	// UpdateCredential within the same transaction
	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.VerifyContactCredential(context.Background(), accountID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestVerifyContactCredential_PhoneFallback tests that VerifyContactCredential falls back to phone when no email credential exists
func TestVerifyContactCredential_PhoneFallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-001"
	now := time.Now()

	// All operations run inside a single transaction (RunInTransaction)
	mock.ExpectBegin()

	// Mock FindByIDTx for requireActiveAccount (inside transaction)
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

	// FindByAccountAndTypeForUpdate for email — not found
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypeEmail).
		WillReturnError(repository.ErrCredentialNotFound)

	// FindByAccountAndTypeForUpdate for phone — returns one unverified credential
	phoneRows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier",
		"credential_value", "verified", "primary_credential", "metadata",
		"created_at", "updated_at", "verified_at", "last_used_at",
	}).AddRow(
		"cred-phone-001", accountID, domain.CredentialTypePhone, "+1234567890",
		"", false, true, []byte("{}"),
		now, now, nil, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePhone).
		WillReturnRows(phoneRows)

	// UpdateCredential within the same transaction
	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = accountService.VerifyContactCredential(context.Background(), accountID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestVerifyContactCredential_NoCredentialFound tests VerifyContactCredential when neither email nor phone exists
func TestVerifyContactCredential_NoCredentialFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-no-creds"
	now := time.Now()

	// All operations run inside a single transaction (RunInTransaction)
	mock.ExpectBegin()

	// Mock FindByIDTx for requireActiveAccount (inside transaction)
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

	// FindByAccountAndTypeForUpdate for email — not found
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypeEmail).
		WillReturnError(repository.ErrCredentialNotFound)

	// FindByAccountAndTypeForUpdate for phone — not found
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePhone).
		WillReturnError(repository.ErrCredentialNotFound)

	// Transaction rolls back because the inner function returned ErrCredentialNotFound
	mock.ExpectRollback()

	err = accountService.VerifyContactCredential(context.Background(), accountID)

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-001"

	// All DB operations now happen inside a single transaction
	mock.ExpectBegin()

	// Mock FindByIDTx for account active check inside transaction
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-001"
	now := time.Now()

	// All DB operations now happen inside a single transaction
	mock.ExpectBegin()

	// Mock FindByIDTx for account active check inside transaction
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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-001"
	identityID := "fi-001"

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	// The account check and password/identity checks are all INSIDE the transaction (TOCTOU fix)
	mock.ExpectBegin()

	// Mock FindByIDTx for requireActiveAccount inside transaction
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	// Mock FindByAccountAndTypeTx for password check inside transaction
	mock.ExpectQuery("SELECT (.+) FROM account_credentials WHERE account_id").
		WithArgs(accountID, domain.CredentialTypePassword).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "account_id", "credential_type", "identifier", "credential_value",
			"verified", "primary_credential", "metadata", "created_at", "updated_at",
			"verified_at", "last_used_at",
		}).AddRow("cred-001", accountID, domain.CredentialTypePassword, nil, "hashed-pw",
			true, true, []byte("{}"), now, now, nil, nil))

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

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	accountID := "account-001"
	identityID := "nonexistent"

	// Mock FindByID for requireActiveAccount (now inside transaction)
	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		accountID, "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	// The account check and password check are now INSIDE the transaction (TOCTOU fix)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(accountID).
		WillReturnRows(accountRows)

	// Mock FindByAccountAndTypeTx for password check inside transaction
	mock.ExpectQuery("SELECT (.+) FROM account_credentials WHERE account_id").
		WithArgs(accountID, domain.CredentialTypePassword).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "account_id", "credential_type", "identifier", "credential_value",
			"verified", "primary_credential", "metadata", "created_at", "updated_at",
			"verified_at", "last_used_at",
		}).AddRow("cred-001", accountID, domain.CredentialTypePassword, nil, "hashed-pw",
			true, true, []byte("{}"), now, now, nil, nil))

	mock.ExpectExec("UPDATE federated_identities SET deleted_at").
		WithArgs(sqlmock.AnyArg(), identityID, accountID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = accountService.UnbindFederatedIdentity(context.Background(), accountID, identityID)

	assert.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrFederatedIdentityNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetOptions_LateBind tests late-binding via SetOptions
func TestSetOptions_LateBind(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	svc := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	svc.SetOptions(&AccountServiceOptions{
		SessionRevoker:      &stubSessionRevoker{},
		OAuth2ClientDeleter: &stubOAuth2ClientDeleter{},
	})

	assert.NotNil(t, svc.sessionRevoker)
	assert.NotNil(t, svc.oauth2ClientDeleter)
}

// TestSetOptions_DuplicateCallLogsWarning tests that a second SetOptions call produces a warning log.
func TestSetOptions_DuplicateCallLogsWarning(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	svc := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, logger, nil)

	// First call should apply without warning.
	svc.SetOptions(&AccountServiceOptions{
		SessionRevoker:      &stubSessionRevoker{},
		OAuth2ClientDeleter: &stubOAuth2ClientDeleter{},
	})
	assert.Equal(t, 0, logs.Len(), "first call should not produce warnings")

	// Second call should log a warning and not overwrite the first.
	svc.SetOptions(&AccountServiceOptions{
		SessionRevoker:      &stubSessionRevoker{},
		OAuth2ClientDeleter: &stubOAuth2ClientDeleter{},
	})
	assert.Equal(t, 1, logs.Len(), "second call should produce one warning")
	assert.Equal(t, "SetOptions called multiple times; subsequent calls are ignored", logs.All()[0].Message)
}

// TestSetOptions_FakeImplementation tests that SetOptions works with non-impl types
func TestSetOptions_FakeImplementation(t *testing.T) {
	fake := &fakeAccountService{}
	fake.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}}) // should not panic
}

// fakeAccountService is a non-pointer-type AccountService used to test interface methods.
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
func (f *fakeAccountService) FindByUsernameWithPasswordCredential(_ context.Context, _ string) (*domain.Account, *domain.Credential, error) {
	return nil, nil, nil
}
func (f *fakeAccountService) UpdateAccount(_ context.Context, _ *domain.Account) error  { return nil }
func (f *fakeAccountService) SoftDeleteAccount(_ context.Context, _ string) error       { return nil }
func (f *fakeAccountService) VerifyContactCredential(_ context.Context, _ string) error { return nil }
func (f *fakeAccountService) ChangePassword(_ context.Context, _, _, _ string) error    { return nil }
func (f *fakeAccountService) AdminChangePassword(_ context.Context, _, _ string) error  { return nil }
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
func (f *fakeAccountService) SetOptions(_ *AccountServiceOptions) {}

// ──────────────────────────────────────────────
// validateUsername
// ──────────────────────────────────────────────

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid simple", "alice", nil},
		{"valid with digits", "user123", nil},
		{"valid with hyphen", "my-user", nil},
		{"valid with dot", "my.user", nil},
		{"valid with underscore", "my_user", nil},
		{"valid minimum length", "ab", nil},
		{"empty username", "", ErrUsernameEmpty},
		{"too short", "a", ErrUsernameTooShort},
		{"too long", string(make([]byte, 65)), ErrUsernameTooLong},
		{"uppercase letter", "Alice", ErrUsernameInvalidChars},
		{"space in name", "my user", ErrUsernameInvalidChars},
		{"special char", "user@host", ErrUsernameInvalidChars},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ──────────────────────────────────────────────
// nonNilMap
// ──────────────────────────────────────────────

func TestNonNilMap(t *testing.T) {
	t.Run("nil returns empty map", func(t *testing.T) {
		result := nonNilMap(nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("non-nil returns same map", func(t *testing.T) {
		input := map[string]any{"key": "value"}
		result := nonNilMap(input)
		assert.Equal(t, input, result)
	})
}

// ──────────────────────────────────────────────
// FindByUsernameWithPasswordCredential
// ──────────────────────────────────────────────

func TestFindByUsernameWithPasswordCredential(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		// account columns
		"a.id", "a.username", "a.display_name", "a.avatar_url", "a.status",
		"a.locale", "a.timezone", "a.metadata", "a.created_at", "a.updated_at", "a.deleted_at",
		// credential columns (nullable due to LEFT JOIN)
		"c.id", "c.account_id", "c.credential_type", "c.identifier", "c.credential_value",
		"c.verified", "c.primary_credential", "c.metadata", "c.created_at", "c.updated_at",
		"c.verified_at", "c.last_used_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
		"cred-001", "account-001", domain.CredentialTypePassword, "test@example.com",
		"hashed-pw", true, true, []byte("{}"), now, now, nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM accounts (.+) JOIN account_credentials").
		WithArgs("testuser", domain.CredentialTypePassword).
		WillReturnRows(rows)

	account, cred, err := accountService.FindByUsernameWithPasswordCredential(context.Background(), "testuser")

	require.NoError(t, err)
	require.NotNil(t, account)
	require.NotNil(t, cred)
	assert.Equal(t, "account-001", account.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFindByUsernameWithPasswordCredential_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	mock.ExpectQuery("SELECT (.+) FROM accounts (.+) JOIN account_credentials").
		WithArgs("nonexistent", domain.CredentialTypePassword).
		WillReturnError(sql.ErrNoRows)

	account, cred, err := accountService.FindByUsernameWithPasswordCredential(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Nil(t, cred)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// AssignRole error paths
// ──────────────────────────────────────────────

func TestAssignRole_AccountNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = accountService.AssignRole(context.Background(), "nonexistent", "role-001")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountNotActive)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAssignRole_RoleNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusActive,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)

	mock.ExpectQuery("SELECT (.+) FROM roles WHERE id").
		WithArgs("nonexistent-role").
		WillReturnError(sql.ErrNoRows)

	mock.ExpectRollback()

	err = accountService.AssignRole(context.Background(), "account-001", "nonexistent-role")
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// ChangePassword error paths
// ──────────────────────────────────────────────

func TestChangePassword_SamePassword(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	accountService.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}, OAuth2ClientDeleter: &stubOAuth2ClientDeleter{}})

	err = accountService.ChangePassword(context.Background(), "account-001", "SamePassword123!", "SamePassword123!")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSamePassword)
}

func TestChangePassword_IncorrectOldPassword(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	accountService.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}, OAuth2ClientDeleter: &stubOAuth2ClientDeleter{}})

	accountID := "test-account-id"
	correctPassword := "CorrectPass123!"
	wrongPassword := "WrongPassword456!"
	newPassword := "NewPassword789!"

	// Generate hash for the correct password (not the wrong one)
	correctHash, err := domain.HashPassword(correctPassword)
	require.NoError(t, err)

	mock.ExpectBegin()

	// Mock FindByIDTx for account active check
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

	// Mock password credential lookup with the correct hash
	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier", "credential_value",
		"verified", "primary_credential", "metadata", "created_at", "updated_at",
		"verified_at", "last_used_at",
	}).AddRow(
		"cred-id", accountID, domain.CredentialTypePassword, "test@example.com", correctHash,
		true, true, []byte("{}"), time.Now(), time.Now(), nil, nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePassword).
		WillReturnRows(rows)

	mock.ExpectRollback()

	// Try to change password with wrong old password
	err = accountService.ChangePassword(context.Background(), accountID, wrongPassword, newPassword)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrIncorrectOldPassword)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_NilSessionRevoker(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	err = accountService.ChangePassword(context.Background(), "account-001", "OldPassword1234!", "NewPassword5678!")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SessionRevoker not configured")
}

// ──────────────────────────────────────────────
// BindFederatedIdentity error paths
// ──────────────────────────────────────────────

func TestBindFederatedIdentity_InactiveAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	now := time.Now()
	// Return a suspended account
	accountRows := sqlmock.NewRows([]string{
		"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
	}).AddRow(
		"account-001", "testuser", "Test User", nil, domain.AccountStatusSuspended,
		"en", "UTC", []byte("{}"), now, now, nil,
	)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs("account-001").
		WillReturnRows(accountRows)
	mock.ExpectRollback()

	profile := map[string]interface{}{"name": "Test User"}
	err = accountService.BindFederatedIdentity(context.Background(), "account-001", domain.ProviderGoogle, "google-user-123", profile)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountNotActive)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// SoftDeleteAccount error paths
// ──────────────────────────────────────────────

func TestSoftDeleteAccount_NilSessionRevoker(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	err = accountService.SoftDeleteAccount(context.Background(), "account-001")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SessionRevoker not configured")
}

func TestSoftDeleteAccount_NilOAuth2ClientDeleter(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)
	// Set session revoker but NOT the OAuth2 deleter
	accountService.SetOptions(&AccountServiceOptions{SessionRevoker: &stubSessionRevoker{}})

	err = accountService.SoftDeleteAccount(context.Background(), "account-001")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OAuth2ClientDeleter not configured")
}

func TestSoftDeleteAccount_EmptyID(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo, nil, nil, nil)

	err = accountService.SoftDeleteAccount(context.Background(), "")

	assert.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrAccountIDRequired)
}
