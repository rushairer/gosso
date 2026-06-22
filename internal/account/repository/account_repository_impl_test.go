package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/utility"
)

func newTestAccount() *domain.Account {
	username := "testuser"
	avatarURL := "https://example.com/avatar.png"
	return &domain.Account{
		ID:          "account-001",
		Username:    &username,
		DisplayName: "Test User",
		AvatarURL:   &avatarURL,
		Status:      domain.AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    map[string]any{"key": "value"},
		CreatedAt:   time.Now().Add(-1 * time.Hour),
		UpdatedAt:   time.Now().Add(-1 * time.Hour),
	}
}

func accountColumns() []string {
	return []string{"id", "username", "display_name", "avatar_url", "status",
		"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at"}
}

func accountRowValues(a *domain.Account) []driver.Value {
	md, _ := json.Marshal(a.Metadata)
	return []driver.Value{a.ID, a.Username, a.DisplayName, a.AvatarURL, string(a.Status),
		a.Locale, a.Timezone, md, a.CreatedAt, a.UpdatedAt, a.DeletedAt}
}

// ──────────────────────────────────────────────
// CreateAccount
// ──────────────────────────────────────────────

func TestCreateAccount_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	a := newTestAccount()
	mock.ExpectExec("INSERT INTO accounts").
		WithArgs(a.ID, a.Username, a.DisplayName, a.AvatarURL, string(a.Status),
			a.Locale, a.Timezone, sqlmock.AnyArg(), a.CreatedAt, a.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewAccountRepository(db)
	err = repo.CreateAccount(context.Background(), tx, a)

	require.NoError(t, err)
}

// ──────────────────────────────────────────────
// FindByID
// ──────────────────────────────────────────────

func TestFindByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	a := newTestAccount()
	rows := sqlmock.NewRows(accountColumns()).AddRow(accountRowValues(a)...)
	mock.ExpectQuery("SELECT .+ FROM accounts WHERE id").WithArgs("account-001").WillReturnRows(rows)

	repo := NewAccountRepository(db)
	result, err := repo.FindByID(context.Background(), "account-001")

	require.NoError(t, err)
	assert.Equal(t, "account-001", result.ID)
	assert.Equal(t, "testuser", *result.Username)
	assert.Equal(t, "Test User", result.DisplayName)
	assert.Equal(t, domain.AccountStatusActive, result.Status)
	assert.Equal(t, "en", result.Locale)
	assert.Equal(t, "value", result.Metadata["key"])
	assert.Nil(t, result.DeletedAt)
}

func TestFindByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM accounts WHERE id").WithArgs("nonexistent").WillReturnRows(sqlmock.NewRows(accountColumns()))

	repo := NewAccountRepository(db)
	_, err = repo.FindByID(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account not found")
}

// ──────────────────────────────────────────────
// FindByUsername
// ──────────────────────────────────────────────

func TestFindByUsername_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	a := newTestAccount()
	rows := sqlmock.NewRows(accountColumns()).AddRow(accountRowValues(a)...)
	mock.ExpectQuery("SELECT .+ FROM accounts WHERE username").WithArgs("testuser").WillReturnRows(rows)

	repo := NewAccountRepository(db)
	result, err := repo.FindByUsername(context.Background(), "testuser")

	require.NoError(t, err)
	assert.Equal(t, "account-001", result.ID)
	assert.Equal(t, "testuser", *result.Username)
}

func TestFindByUsername_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM accounts WHERE username").WithArgs("nobody").WillReturnRows(sqlmock.NewRows(accountColumns()))

	repo := NewAccountRepository(db)
	_, err = repo.FindByUsername(context.Background(), "nobody")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account not found")
	assert.True(t, errors.Is(err, ErrAccountNotFound))
}

// ──────────────────────────────────────────────
// UpdateAccount
// ──────────────────────────────────────────────

func TestUpdateAccount_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	a := newTestAccount()
	a.DisplayName = "Updated Name"
	mock.ExpectExec("UPDATE accounts").
		WithArgs(a.Username, a.DisplayName, a.AvatarURL, string(a.Status),
			a.Locale, a.Timezone, sqlmock.AnyArg(), sqlmock.AnyArg(), a.ID, a.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewAccountRepository(db)
	err = repo.UpdateAccount(context.Background(), tx, a, a.UpdatedAt)

	require.NoError(t, err)
}

func TestUpdateAccount_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	a := newTestAccount()
	mock.ExpectExec("UPDATE accounts").
		WithArgs(a.Username, a.DisplayName, a.AvatarURL, string(a.Status),
			a.Locale, a.Timezone, sqlmock.AnyArg(), sqlmock.AnyArg(), a.ID, a.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 0))

	// When rowsAffected == 0, the code re-reads to distinguish not-found from concurrent modification
	mock.ExpectQuery("SELECT (.+) FROM accounts WHERE id").
		WithArgs(a.ID).
		WillReturnError(sql.ErrNoRows)

	repo := NewAccountRepository(db)
	err = repo.UpdateAccount(context.Background(), tx, a, a.UpdatedAt)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account not found")
	assert.True(t, errors.Is(err, ErrAccountNotFound))
}

// ──────────────────────────────────────────────
// SoftDeleteAccount
// ──────────────────────────────────────────────

func TestSoftDeleteAccount_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE accounts").
		WithArgs(deletedAt, string(domain.AccountStatusDeleted), "account-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewAccountRepository(db)
	err = repo.SoftDeleteAccountByID(context.Background(), tx, "account-001", deletedAt)

	require.NoError(t, err)
}

func TestSoftDeleteAccount_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE accounts").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewAccountRepository(db)
	err = repo.SoftDeleteAccountByID(context.Background(), tx, "nonexistent", time.Now())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account not found")
	assert.True(t, errors.Is(err, ErrAccountNotFound))
}

// ──────────────────────────────────────────────
// FindAll
// ──────────────────────────────────────────────

func TestFindAll_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	countRows := sqlmock.NewRows([]string{"count"}).AddRow(2)
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(countRows)

	a1 := newTestAccount()
	a2 := &domain.Account{
		ID: "account-002", Username: utility.Ptr[string]("user2"), DisplayName: "User Two",
		Status: domain.AccountStatusActive, Locale: "en", Timezone: "UTC",
		Metadata: map[string]any{}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	selectRows := sqlmock.NewRows(accountColumns()).
		AddRow(accountRowValues(a1)...).
		AddRow(accountRowValues(a2)...)
	mock.ExpectQuery("SELECT .+ FROM accounts WHERE").WillReturnRows(selectRows)

	repo := NewAccountRepository(db)
	accounts, total, err := repo.FindAll(context.Background(), 1, 20, "")

	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, accounts, 2)
	assert.Equal(t, "account-001", accounts[0].ID)
	assert.Equal(t, "account-002", accounts[1].ID)
}

func TestFindAll_WithStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	countRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery("SELECT COUNT").WithArgs("active").WillReturnRows(countRows)

	a := newTestAccount()
	selectRows := sqlmock.NewRows(accountColumns()).AddRow(accountRowValues(a)...)
	mock.ExpectQuery("SELECT .+ FROM accounts WHERE").WillReturnRows(selectRows)

	repo := NewAccountRepository(db)
	accounts, total, err := repo.FindAll(context.Background(), 1, 20, "active")

	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, accounts, 1)
}

func TestFindAll_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	countRows := sqlmock.NewRows([]string{"count"}).AddRow(0)
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(countRows)

	repo := NewAccountRepository(db)
	accounts, total, err := repo.FindAll(context.Background(), 1, 20, "")

	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, accounts)
}

func TestFindAll_DefaultPagination(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// page < 1 should default to 1, pageSize < 1 should default to 20
	countRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(countRows)

	a := newTestAccount()
	selectRows := sqlmock.NewRows(accountColumns()).AddRow(accountRowValues(a)...)
	mock.ExpectQuery("SELECT .+ FROM accounts WHERE").WillReturnRows(selectRows)

	repo := NewAccountRepository(db)
	accounts, total, err := repo.FindAll(context.Background(), 0, 0, "")

	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, accounts, 1)
}

// ──────────────────────────────────────────────
// SuspendAccount
// ──────────────────────────────────────────────

func TestSuspendAccount_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE accounts SET status").
		WithArgs(sqlmock.AnyArg(), "account-001", "suspended", "active").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewAccountRepository(db)
	err = repo.SuspendAccount(context.Background(), tx, "account-001")

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSuspendAccount_InvalidTransition(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE accounts SET status").
		WithArgs(sqlmock.AnyArg(), "account-001", "suspended", "active").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewAccountRepository(db)
	err = repo.SuspendAccount(context.Background(), tx, "account-001")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidStatusTransition))
}

// ──────────────────────────────────────────────
// ActivateAccount
// ──────────────────────────────────────────────

func TestActivateAccount_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE accounts SET status").
		WithArgs(sqlmock.AnyArg(), "account-001", "active", "suspended").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewAccountRepository(db)
	err = repo.ActivateAccount(context.Background(), tx, "account-001")

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestActivateAccount_InvalidTransition(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE accounts SET status").
		WithArgs(sqlmock.AnyArg(), "account-001", "active", "suspended").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewAccountRepository(db)
	err = repo.ActivateAccount(context.Background(), tx, "account-001")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidStatusTransition))
}
