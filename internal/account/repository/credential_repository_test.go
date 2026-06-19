package repository

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/account/domain"
)

func newTestCredential(accountID string, credType domain.CredentialType, identifier string) *domain.Credential {
	return &domain.Credential{
		ID:                "cred-001",
		AccountID:         accountID,
		Type:              credType,
		Identifier:        &identifier,
		Value:             "hashed-password-value",
		Verified:          true,
		PrimaryCredential: true,
		Metadata:          map[string]any{"key": "value"},
		CreatedAt:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		VerifiedAt:        nil,
		LastUsedAt:        nil,
		DeletedAt:         nil,
	}
}

func credentialColumns() []string {
	return []string{
		"id", "account_id", "credential_type", "identifier", "credential_value",
		"verified", "primary_credential", "metadata", "created_at", "updated_at",
		"verified_at", "last_used_at",
	}
}

func credentialRowValues(c *domain.Credential) []driver.Value {
	md, _ := json.Marshal(c.Metadata)
	return []driver.Value{
		c.ID, c.AccountID, string(c.Type), c.Identifier, c.Value,
		c.Verified, c.PrimaryCredential, md, c.CreatedAt, c.UpdatedAt,
		c.VerifiedAt, c.LastUsedAt,
	}
}

// ──────────────────────────────────────────────
// NewCredentialRepository
// ──────────────────────────────────────────────

func TestNewCredentialRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewCredentialRepository(db)
	assert.NotNil(t, repo)
}

// ──────────────────────────────────────────────
// FindByAccountAndType
// ──────────────────────────────────────────────

func TestFindByAccountAndType_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	c := newTestCredential("account-001", domain.CredentialTypePassword, "testuser")
	rows := sqlmock.NewRows(credentialColumns()).AddRow(credentialRowValues(c)...)
	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE account_id").
		WithArgs("account-001", domain.CredentialTypePassword).
		WillReturnRows(rows)

	repo := NewCredentialRepository(db)
	credentials, err := repo.FindByAccountAndType(context.Background(), "account-001", domain.CredentialTypePassword)

	require.NoError(t, err)
	require.Len(t, credentials, 1)
	assert.Equal(t, "cred-001", credentials[0].ID)
	assert.Equal(t, "account-001", credentials[0].AccountID)
	assert.Equal(t, domain.CredentialTypePassword, credentials[0].Type)
	assert.Equal(t, "testuser", *credentials[0].Identifier)
	assert.True(t, credentials[0].Verified)
	assert.True(t, credentials[0].PrimaryCredential)
	assert.Equal(t, "value", credentials[0].Metadata["key"])
	assert.Nil(t, credentials[0].DeletedAt)
}

func TestFindByAccountAndType_EmptyResult(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE account_id").
		WithArgs("account-001", domain.CredentialTypePassword).
		WillReturnRows(sqlmock.NewRows(credentialColumns()))

	repo := NewCredentialRepository(db)
	credentials, err := repo.FindByAccountAndType(context.Background(), "account-001", domain.CredentialTypePassword)

	require.NoError(t, err)
	assert.Empty(t, credentials)
}

// ──────────────────────────────────────────────
// FindByTypeAndIdentifier
// ──────────────────────────────────────────────

func TestFindByTypeAndIdentifier_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	email := "test@example.com"
	c := &domain.Credential{
		ID:                "cred-002",
		AccountID:         "account-001",
		Type:              domain.CredentialTypeEmail,
		Identifier:        &email,
		Value:             "",
		Verified:          false,
		PrimaryCredential: false,
		Metadata:          map[string]any{},
		CreatedAt:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		VerifiedAt:        nil,
		LastUsedAt:        nil,
		DeletedAt:         nil,
	}
	rows := sqlmock.NewRows(credentialColumns()).AddRow(credentialRowValues(c)...)
	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE credential_type").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnRows(rows)

	repo := NewCredentialRepository(db)
	result, err := repo.FindByTypeAndIdentifier(context.Background(), domain.CredentialTypeEmail, "test@example.com")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "cred-002", result.ID)
	assert.Equal(t, "account-001", result.AccountID)
	assert.Equal(t, domain.CredentialTypeEmail, result.Type)
	assert.Equal(t, "test@example.com", *result.Identifier)
}

func TestFindByTypeAndIdentifier_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE credential_type").
		WithArgs(domain.CredentialTypeEmail, "nonexistent@example.com").
		WillReturnRows(sqlmock.NewRows(credentialColumns()))

	repo := NewCredentialRepository(db)
	_, err = repo.FindByTypeAndIdentifier(context.Background(), domain.CredentialTypeEmail, "nonexistent@example.com")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
}

// ──────────────────────────────────────────────
// FindPasswordCredential
// ──────────────────────────────────────────────

func TestFindPasswordCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	c := newTestCredential("account-001", domain.CredentialTypePassword, "")
	rows := sqlmock.NewRows(credentialColumns()).AddRow(credentialRowValues(c)...)
	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE account_id").
		WithArgs("account-001", domain.CredentialTypePassword).
		WillReturnRows(rows)

	repo := NewCredentialRepository(db)
	result, err := repo.FindPasswordCredential(context.Background(), "account-001")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "cred-001", result.ID)
	assert.Equal(t, domain.CredentialTypePassword, result.Type)
}

func TestFindPasswordCredential_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE account_id").
		WithArgs("account-001", domain.CredentialTypePassword).
		WillReturnRows(sqlmock.NewRows(credentialColumns()))

	repo := NewCredentialRepository(db)
	_, err = repo.FindPasswordCredential(context.Background(), "account-001")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
	assert.True(t, errors.Is(err, ErrCredentialNotFound))
}

// ──────────────────────────────────────────────
// SoftDeleteCredentialsByAccount
// ──────────────────────────────────────────────

func TestSoftDeleteCredentialsByAccount_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE account_credentials").
		WithArgs(deletedAt, "account-001").
		WillReturnResult(sqlmock.NewResult(0, 3))

	repo := NewCredentialRepository(db)
	err = repo.SoftDeleteCredentialsByAccount(context.Background(), tx, "account-001", deletedAt)

	require.NoError(t, err)
}

// ──────────────────────────────────────────────
// SoftDeleteCredential
// ──────────────────────────────────────────────

func TestSoftDeleteCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE account_credentials").
		WithArgs(deletedAt, "cred-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewCredentialRepository(db)
	err = repo.SoftDeleteCredential(context.Background(), tx, "cred-001", deletedAt)

	require.NoError(t, err)
}

func TestSoftDeleteCredential_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewCredentialRepository(db)
	err = repo.SoftDeleteCredential(context.Background(), tx, "nonexistent", time.Now())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
	assert.True(t, errors.Is(err, ErrCredentialNotFound))
}

// ──────────────────────────────────────────────
// CreateCredentials
// ──────────────────────────────────────────────

func TestCreateCredentials_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestCredential("account-001", domain.CredentialTypePassword, "testuser")
	mock.ExpectExec("INSERT INTO account_credentials").
		WithArgs(c.ID, c.AccountID, string(c.Type), c.Identifier, c.Value,
			c.Verified, c.PrimaryCredential, sqlmock.AnyArg(),
			c.CreatedAt, c.UpdatedAt, c.VerifiedAt, c.LastUsedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewCredentialRepository(db)
	err = repo.CreateCredentials(context.Background(), tx, []*domain.Credential{c})

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateCredentials_EmptySlice(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewCredentialRepository(db)
	err = repo.CreateCredentials(context.Background(), nil, []*domain.Credential{})

	require.NoError(t, err)
}

// ──────────────────────────────────────────────
// UpdateCredential
// ──────────────────────────────────────────────

func TestUpdateCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestCredential("account-001", domain.CredentialTypePassword, "testuser")
	mock.ExpectExec("UPDATE account_credentials").
		WithArgs(c.Identifier, c.Value, c.Verified, c.PrimaryCredential,
			sqlmock.AnyArg(), c.VerifiedAt, c.LastUsedAt, c.ID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewCredentialRepository(db)
	err = repo.UpdateCredential(context.Background(), tx, c)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestCredential("account-001", domain.CredentialTypePassword, "testuser")
	mock.ExpectExec("UPDATE account_credentials").
		WithArgs(c.Identifier, c.Value, c.Verified, c.PrimaryCredential,
			sqlmock.AnyArg(), c.VerifiedAt, c.LastUsedAt, c.ID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewCredentialRepository(db)
	err = repo.UpdateCredential(context.Background(), tx, c)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
	assert.True(t, errors.Is(err, ErrCredentialNotFound))
}

// ──────────────────────────────────────────────
// FindByAccountAndTypeForUpdate
// ──────────────────────────────────────────────

func TestFindByAccountAndTypeForUpdate_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestCredential("account-001", domain.CredentialTypePassword, "testuser")
	rows := sqlmock.NewRows(credentialColumns()).AddRow(credentialRowValues(c)...)
	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE account_id .+ FOR UPDATE").
		WithArgs("account-001", domain.CredentialTypePassword).
		WillReturnRows(rows)

	repo := NewCredentialRepository(db)
	credentials, err := repo.FindByAccountAndTypeForUpdate(context.Background(), tx, "account-001", domain.CredentialTypePassword)

	require.NoError(t, err)
	require.Len(t, credentials, 1)
	assert.Equal(t, "cred-001", credentials[0].ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFindByAccountAndTypeForUpdate_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	rows := sqlmock.NewRows(credentialColumns())
	mock.ExpectQuery("SELECT .+ FROM account_credentials WHERE account_id .+ FOR UPDATE").
		WithArgs("account-001", domain.CredentialTypePassword).
		WillReturnRows(rows)

	repo := NewCredentialRepository(db)
	credentials, err := repo.FindByAccountAndTypeForUpdate(context.Background(), tx, "account-001", domain.CredentialTypePassword)

	require.NoError(t, err)
	assert.Empty(t, credentials)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// VerifyFirstUnverifiedTOTP
// ──────────────────────────────────────────────

func TestVerifyFirstUnverifiedTOTP_Found(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE account_credentials").
		WithArgs("account-001", "totp").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewCredentialRepository(db)
	updated, err := repo.VerifyFirstUnverifiedTOTP(context.Background(), tx, "account-001")

	require.NoError(t, err)
	assert.True(t, updated)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestVerifyFirstUnverifiedTOTP_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE account_credentials").
		WithArgs("account-001", "totp").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewCredentialRepository(db)
	updated, err := repo.VerifyFirstUnverifiedTOTP(context.Background(), tx, "account-001")

	require.NoError(t, err)
	assert.False(t, updated)
	assert.NoError(t, mock.ExpectationsWereMet())
}
