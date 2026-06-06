package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
)

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

	// 2b. Expect querying whether username exists (executed inside transaction)
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE username").
		WithArgs("testuser").
		WillReturnError(sql.ErrNoRows)

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

	accountID := "test-account-id"
	oldPassword := "OldPassword123!"
	newPassword := "NewPassword456!"

	// Generate a real bcrypt hash for the old password
	oldHash, err := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier", "credential_value",
		"verified", "primary_credential", "metadata", "created_at", "verified_at", "last_used_at", "deleted_at",
	}).AddRow(
		"cred-id", accountID, domain.CredentialTypePassword, "test@example.com", string(oldHash),
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

	accountID := "test-account-id"

	// Set mock expectations
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
