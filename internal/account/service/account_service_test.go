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
	assert.Contains(t, err.Error(), "email already registered")

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

	// Expect FindByID for idempotency check (account not deleted)
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
