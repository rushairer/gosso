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

func newTestFederatedIdentity() *domain.FederatedIdentity {
	return &domain.FederatedIdentity{
		ID:             "fid-001",
		AccountID:      "account-001",
		Provider:       domain.ProviderGoogle,
		ProviderUserID: "google-user-123",
		Profile:        map[string]any{"name": "Test User", "email": "test@example.com"},
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		UpdatedAt:      time.Now().Add(-1 * time.Hour),
	}
}

func federatedIdentityColumns() []string {
	return []string{"id", "account_id", "provider", "provider_user_id", "profile", "created_at", "updated_at", "deleted_at"}
}

func federatedIdentityRowValues(fi *domain.FederatedIdentity) []driver.Value {
	pj, _ := json.Marshal(fi.Profile)
	return []driver.Value{fi.ID, fi.AccountID, string(fi.Provider), fi.ProviderUserID, pj, fi.CreatedAt, fi.UpdatedAt, fi.DeletedAt}
}

// ──────────────────────────────────────────────
// NewFederatedIdentityRepository
// ──────────────────────────────────────────────

func TestNewFederatedIdentityRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewFederatedIdentityRepository(db)
	assert.NotNil(t, repo)
}

// ──────────────────────────────────────────────
// FindByProvider
// ──────────────────────────────────────────────

func TestFindByProvider_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	fi := newTestFederatedIdentity()
	rows := sqlmock.NewRows(federatedIdentityColumns()).AddRow(federatedIdentityRowValues(fi)...)
	mock.ExpectQuery("SELECT .+ FROM federated_identities WHERE provider").WithArgs(string(domain.ProviderGoogle), "google-user-123").WillReturnRows(rows)

	repo := NewFederatedIdentityRepository(db)
	result, err := repo.FindByProvider(context.Background(), domain.ProviderGoogle, "google-user-123")

	require.NoError(t, err)
	assert.Equal(t, "fid-001", result.ID)
	assert.Equal(t, "account-001", result.AccountID)
	assert.Equal(t, domain.ProviderGoogle, result.Provider)
	assert.Equal(t, "google-user-123", result.ProviderUserID)
	assert.Equal(t, "Test User", result.Profile["name"])
	assert.Equal(t, "test@example.com", result.Profile["email"])
	assert.Nil(t, result.DeletedAt)
}

func TestFindByProvider_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM federated_identities WHERE provider").WithArgs("github", "nonexistent").WillReturnRows(sqlmock.NewRows(federatedIdentityColumns()))

	repo := NewFederatedIdentityRepository(db)
	_, err = repo.FindByProvider(context.Background(), domain.ProviderGitHub, "nonexistent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "federated identity not found")
}

// ──────────────────────────────────────────────
// FindByAccountID
// ──────────────────────────────────────────────

func TestFindByAccountID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	fi1 := newTestFederatedIdentity()
	fi2 := &domain.FederatedIdentity{
		ID:             "fid-002",
		AccountID:      "account-001",
		Provider:       domain.ProviderGitHub,
		ProviderUserID: "gh-user-456",
		Profile:        map[string]any{"login": "ghuser"},
		CreatedAt:      time.Now().Add(-2 * time.Hour),
		UpdatedAt:      time.Now().Add(-2 * time.Hour),
	}

	rows := sqlmock.NewRows(federatedIdentityColumns()).
		AddRow(federatedIdentityRowValues(fi1)...).
		AddRow(federatedIdentityRowValues(fi2)...)
	mock.ExpectQuery("SELECT .+ FROM federated_identities WHERE account_id").WithArgs("account-001").WillReturnRows(rows)

	repo := NewFederatedIdentityRepository(db)
	identities, err := repo.FindByAccountID(context.Background(), "account-001")

	require.NoError(t, err)
	assert.Len(t, identities, 2)
	assert.Equal(t, "fid-001", identities[0].ID)
	assert.Equal(t, domain.ProviderGoogle, identities[0].Provider)
	assert.Equal(t, "fid-002", identities[1].ID)
	assert.Equal(t, domain.ProviderGitHub, identities[1].Provider)
}

func TestFindByAccountID_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM federated_identities WHERE account_id").WithArgs("account-empty").WillReturnRows(sqlmock.NewRows(federatedIdentityColumns()))

	repo := NewFederatedIdentityRepository(db)
	identities, err := repo.FindByAccountID(context.Background(), "account-empty")

	require.NoError(t, err)
	assert.Empty(t, identities)
}

// ──────────────────────────────────────────────
// SoftDeleteFederatedIdentitiesByAccountID
// ──────────────────────────────────────────────

func TestSoftDeleteFederatedIdentitiesByAccountID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE federated_identities").
		WithArgs(deletedAt, "account-001").
		WillReturnResult(sqlmock.NewResult(0, 2))

	repo := NewFederatedIdentityRepository(db)
	err = repo.SoftDeleteFederatedIdentitiesByAccountID(context.Background(), tx, "account-001", deletedAt)

	require.NoError(t, err)
}

// ──────────────────────────────────────────────
// SoftDeleteFederatedIdentityByID
// ──────────────────────────────────────────────

func TestSoftDeleteFederatedIdentityByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE federated_identities").
		WithArgs(deletedAt, "fid-001", "account-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewFederatedIdentityRepository(db)
	err = repo.SoftDeleteFederatedIdentityByID(context.Background(), tx, "account-001", "fid-001", deletedAt)

	require.NoError(t, err)
}

func TestSoftDeleteFederatedIdentityByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE federated_identities").
		WithArgs(deletedAt, "nonexistent", "account-001").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewFederatedIdentityRepository(db)
	err = repo.SoftDeleteFederatedIdentityByID(context.Background(), tx, "account-001", "nonexistent", deletedAt)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "federated identity not found")
	assert.True(t, errors.Is(err, ErrFederatedIdentityNotFound))
}

// ──────────────────────────────────────────────
// CreateFederatedIdentity
// ──────────────────────────────────────────────

func TestCreateFederatedIdentity_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	fi := newTestFederatedIdentity()
	mock.ExpectExec("INSERT INTO federated_identities").
		WithArgs(fi.ID, fi.AccountID, string(fi.Provider), fi.ProviderUserID,
			sqlmock.AnyArg(), fi.CreatedAt, fi.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewFederatedIdentityRepository(db)
	err = repo.CreateFederatedIdentity(context.Background(), tx, fi)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
