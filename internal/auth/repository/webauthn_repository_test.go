package repository

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/auth/domain"
)

func newTestWebAuthnCred() *domain.WebAuthnCredential {
	now := time.Now()
	return &domain.WebAuthnCredential{
		ID:              "cred-001",
		AccountID:       "account-001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKey:       []byte("public-key-bytes"),
		SignCount:       5,
		AAGUID:          []byte("aaguid-bytes"),
		Transports:      []string{"internal", "hybrid"},
		AttestationType: "none",
		Name:            "My Passkey",
		Verified:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func webauthnColumns() []string {
	return []string{"id", "account_id", "credential_id", "public_key", "sign_count",
		"aaguid", "transports", "attestation_type", "name", "flags", "verified", "created_at", "updated_at", "last_used_at", "deleted_at"}
}

func webauthnRowValues(c *domain.WebAuthnCredential) []driver.Value {
	trJSON, _ := json.Marshal(c.Transports)
	return []driver.Value{c.ID, c.AccountID, base64.RawURLEncoding.EncodeToString(c.CredentialID), c.PublicKey, c.SignCount,
		c.AAGUID, trJSON, c.AttestationType, c.Name, c.Flags, c.Verified, c.CreatedAt, c.UpdatedAt, c.LastUsedAt, c.DeletedAt}
}

// ──────────────────────────────────────────────
// CreateCredential
// ──────────────────────────────────────────────

func TestWebAuthn_CreateCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestWebAuthnCred()
	mock.ExpectExec("INSERT INTO webauthn_credentials").
		WithArgs(c.ID, c.AccountID, base64.RawURLEncoding.EncodeToString(c.CredentialID), c.PublicKey, c.SignCount,
			c.AAGUID, sqlmock.AnyArg(), c.AttestationType, c.Name, c.Flags, c.Verified, c.CreatedAt, c.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewWebAuthnCredentialRepository(db)
	err = repo.CreateCredential(context.Background(), tx, c)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// FindByCredentialID
// ──────────────────────────────────────────────

func TestWebAuthn_FindByCredentialID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	c := newTestWebAuthnCred()
	rows := sqlmock.NewRows(webauthnColumns()).AddRow(webauthnRowValues(c)...)
	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials WHERE credential_id").WithArgs("cred-id-bytes").WillReturnRows(rows)

	repo := NewWebAuthnCredentialRepository(db)
	result, err := repo.FindByCredentialID(context.Background(), "cred-id-bytes")

	require.NoError(t, err)
	assert.Equal(t, "cred-001", result.ID)
	assert.Equal(t, "account-001", result.AccountID)
	assert.Equal(t, uint32(5), result.SignCount)
	assert.Equal(t, "My Passkey", result.Name)
	assert.Len(t, result.Transports, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestWebAuthn_FindByCredentialID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials WHERE credential_id").WithArgs("nonexistent").WillReturnRows(sqlmock.NewRows(webauthnColumns()))

	repo := NewWebAuthnCredentialRepository(db)
	_, err = repo.FindByCredentialID(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// FindByAccountID
// ──────────────────────────────────────────────

func TestWebAuthn_FindByAccountID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	c1 := newTestWebAuthnCred()
	c2 := &domain.WebAuthnCredential{
		ID: "cred-002", AccountID: "account-001", CredentialID: []byte("cred-2"),
		PublicKey: []byte("pk-2"), Name: "iPhone", Verified: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	rows := sqlmock.NewRows(webauthnColumns()).
		AddRow(webauthnRowValues(c1)...).
		AddRow(webauthnRowValues(c2)...)
	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials WHERE account_id").WithArgs("account-001").WillReturnRows(rows)

	repo := NewWebAuthnCredentialRepository(db)
	results, err := repo.FindByAccountID(context.Background(), "account-001")

	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "cred-001", results[0].ID)
	assert.Equal(t, "cred-002", results[1].ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestWebAuthn_FindByAccountID_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials WHERE account_id").WithArgs("empty-account").WillReturnRows(sqlmock.NewRows(webauthnColumns()))

	repo := NewWebAuthnCredentialRepository(db)
	results, err := repo.FindByAccountID(context.Background(), "empty-account")

	require.NoError(t, err)
	assert.Empty(t, results)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// UpdateCredential
// ──────────────────────────────────────────────

func TestWebAuthn_UpdateCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestWebAuthnCred()
	c.SignCount = 10
	now := time.Now()
	c.LastUsedAt = &now
	mock.ExpectExec("UPDATE webauthn_credentials").
		WithArgs(c.ID, c.SignCount, sqlmock.AnyArg(), c.LastUsedAt, c.Name, c.Flags).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewWebAuthnCredentialRepository(db)
	err = repo.UpdateCredential(context.Background(), tx, c)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// SoftDeleteCredential
// ──────────────────────────────────────────────

func TestWebAuthn_SoftDeleteCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE webauthn_credentials SET deleted_at").
		WithArgs("cred-001", deletedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewWebAuthnCredentialRepository(db)
	err = repo.SoftDeleteCredential(context.Background(), tx, "cred-001", deletedAt)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// SoftDeleteByAccountID
// ──────────────────────────────────────────────

func TestWebAuthn_SoftDeleteByAccountID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE webauthn_credentials SET deleted_at").
		WithArgs("account-001", deletedAt).
		WillReturnResult(sqlmock.NewResult(0, 2))

	repo := NewWebAuthnCredentialRepository(db)
	err = repo.SoftDeleteByAccountID(context.Background(), tx, "account-001", deletedAt)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
