package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

// ──────────────────────────────────────────────
// NewConsentRepository
// ──────────────────────────────────────────────

func TestNewConsentRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewConsentRepository(db)
	assert.NotNil(t, repo)
}

// ──────────────────────────────────────────────
// Upsert
// ──────────────────────────────────────────────

func TestConsentRepo_Upsert_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	now := time.Now()
	consent := &domain.Consent{
		AccountID: "account-001",
		ClientID:  "client-001",
		Scopes:    []string{"openid", "profile"},
		GrantedAt: now,
	}

	scopesJSON, _ := json.Marshal(consent.Scopes)

	mock.ExpectQuery("INSERT INTO oauth2_consents").
		WithArgs(consent.AccountID, consent.ClientID, scopesJSON, consent.GrantedAt).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow("consent-001", now, now))

	repo := NewConsentRepository(db)
	err = repo.Upsert(context.Background(), tx, consent)

	require.NoError(t, err)
	assert.Equal(t, "consent-001", consent.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// FindByAccountAndClient
// ──────────────────────────────────────────────

func TestConsentRepo_FindByAccountAndClient_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	scopesJSON, _ := json.Marshal([]string{"openid", "profile"})

	mock.ExpectQuery("SELECT (.+) FROM oauth2_consents").
		WithArgs("account-001", "client-001").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "account_id", "client_id", "scopes", "granted_at", "created_at", "updated_at"},
		).AddRow("consent-001", "account-001", "client-001", scopesJSON, now, now, now))

	repo := NewConsentRepository(db)
	result, err := repo.FindByAccountAndClient(context.Background(), "account-001", "client-001")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "consent-001", result.ID)
	assert.Equal(t, "account-001", result.AccountID)
	assert.Equal(t, "client-001", result.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, result.Scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConsentRepo_FindByAccountAndClient_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT (.+) FROM oauth2_consents").
		WithArgs("account-001", "nonexistent").
		WillReturnError(sql.ErrNoRows)

	repo := NewConsentRepository(db)
	result, err := repo.FindByAccountAndClient(context.Background(), "account-001", "nonexistent")

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// Delete
// ──────────────────────────────────────────────

func TestConsentRepo_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("DELETE FROM oauth2_consents").
		WithArgs("account-001", "client-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewConsentRepository(db)
	err = repo.Delete(context.Background(), tx, "account-001", "client-001")

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
