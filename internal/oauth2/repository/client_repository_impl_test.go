package repository

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

func newTestOAuth2Client() *domain.OAuth2Client {
	return &domain.OAuth2Client{
		ID:               "client-uuid-001",
		AccountID:        "account-001",
		ClientID:         "cid-abc123",
		ClientSecretHash: "$2a$10$hash",
		Name:             "Test App",
		Description:      "A test app",
		RedirectURIs:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		Scopes:           []string{"openid", "profile"},
		IsConfidential:   true,
	}
}

func clientColumns() []string {
	return []string{"id", "account_id", "client_id", "client_secret_hash", "name", "description",
		"redirect_uris", "post_logout_redirect_uris", "grant_types", "scopes", "is_confidential", "metadata", "created_at", "updated_at"}
}

func clientRowValues(c *domain.OAuth2Client) []driver.Value {
	ru, _ := json.Marshal(c.RedirectURIs)
	plu, _ := json.Marshal(c.PostLogoutRedirectURIs)
	gt, _ := json.Marshal(c.GrantTypes)
	sc, _ := json.Marshal(c.Scopes)
	var md []byte
	if c.Metadata != nil {
		md, _ = json.Marshal(c.Metadata)
	}
	return []driver.Value{c.ID, c.AccountID, c.ClientID, c.ClientSecretHash, c.Name, c.Description,
		ru, plu, gt, sc, c.IsConfidential, md, time.Now(), time.Now()}
}

// ──────────────────────────────────────────────
// FindByClientID
// ──────────────────────────────────────────────

func TestFindByClientID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	c := newTestOAuth2Client()
	rows := sqlmock.NewRows(clientColumns()).AddRow(clientRowValues(c)...)
	mock.ExpectQuery("SELECT .+ FROM oauth2_clients WHERE client_id").WithArgs("cid-abc123").WillReturnRows(rows)

	repo := NewOAuth2ClientRepository(db)
	result, err := repo.FindByClientID(context.Background(), "cid-abc123")

	require.NoError(t, err)
	assert.Equal(t, "cid-abc123", result.ClientID)
	assert.Equal(t, "Test App", result.Name)
	assert.Equal(t, []string{"https://app.example.com/callback"}, result.RedirectURIs)
	assert.True(t, result.IsConfidential)
}

func TestFindByClientID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM oauth2_clients WHERE client_id").WithArgs("nonexistent").WillReturnRows(sqlmock.NewRows(clientColumns()))

	repo := NewOAuth2ClientRepository(db)
	_, err = repo.FindByClientID(context.Background(), "nonexistent")

	assert.ErrorIs(t, err, domain.ErrClientNotFound)
}

// ──────────────────────────────────────────────
// FindByAccountID
// ──────────────────────────────────────────────

func TestFindByAccountID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	c1 := newTestOAuth2Client()
	c2 := &domain.OAuth2Client{
		ID: "client-2", AccountID: "account-001", ClientID: "cid-2",
		Name: "App 2", RedirectURIs: []string{"https://app2.example.com/cb"},
		GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid"},
	}
	rows := sqlmock.NewRows(clientColumns()).
		AddRow(clientRowValues(c1)...).
		AddRow(clientRowValues(c2)...)
	mock.ExpectQuery("SELECT .+ FROM oauth2_clients WHERE account_id").WithArgs("account-001").WillReturnRows(rows)

	repo := NewOAuth2ClientRepository(db)
	results, err := repo.FindByAccountID(context.Background(), "account-001")

	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestFindByAccountID_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM oauth2_clients WHERE account_id").WithArgs("empty-account").WillReturnRows(sqlmock.NewRows(clientColumns()))

	repo := NewOAuth2ClientRepository(db)
	results, err := repo.FindByAccountID(context.Background(), "empty-account")

	require.NoError(t, err)
	assert.Len(t, results, 0)
}

// ──────────────────────────────────────────────
// Create
// ──────────────────────────────────────────────

func TestCreate_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestOAuth2Client()
	mock.ExpectQuery("INSERT INTO oauth2_clients").
		WithArgs(c.AccountID, c.ClientID, c.ClientSecretHash, c.Name, c.Description,
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), c.IsConfidential, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(c.ID, time.Now(), time.Now()))

	repo := NewOAuth2ClientRepository(db)
	err = repo.Create(context.Background(), tx, c)

	require.NoError(t, err)
	assert.NotEmpty(t, c.ID)
}

// ──────────────────────────────────────────────
// Update
// ──────────────────────────────────────────────

func TestUpdate_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestOAuth2Client()
	c.Name = "Updated App"
	mock.ExpectQuery("UPDATE oauth2_clients").
		WithArgs(c.Name, c.Description, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), c.ID).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	repo := NewOAuth2ClientRepository(db)
	err = repo.Update(context.Background(), tx, c)

	require.NoError(t, err)
}

func TestUpdate_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	c := newTestOAuth2Client()
	mock.ExpectQuery("UPDATE oauth2_clients").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}))

	repo := NewOAuth2ClientRepository(db)
	err = repo.Update(context.Background(), tx, c)

	assert.ErrorIs(t, err, domain.ErrClientNotFound)
}

// ──────────────────────────────────────────────
// SoftDelete
// ──────────────────────────────────────────────

func TestSoftDelete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	deletedAt := time.Now()
	mock.ExpectExec("UPDATE oauth2_clients SET deleted_at").
		WithArgs(deletedAt, "client-uuid-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewOAuth2ClientRepository(db)
	err = repo.SoftDelete(context.Background(), tx, "client-uuid-001", deletedAt)

	require.NoError(t, err)
}

func TestSoftDelete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE oauth2_clients SET deleted_at").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewOAuth2ClientRepository(db)
	err = repo.SoftDelete(context.Background(), tx, "nonexistent", time.Now())

	assert.ErrorIs(t, err, domain.ErrClientNotFound)
}

// ──────────────────────────────────────────────
// SoftDeleteByAccountID
// ──────────────────────────────────────────────

func TestSoftDeleteByAccountID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	tx, _ := db.Begin()

	mock.ExpectExec("UPDATE oauth2_clients").
		WithArgs(sqlmock.AnyArg(), "account-001").
		WillReturnResult(sqlmock.NewResult(0, 2))

	repo := NewOAuth2ClientRepository(db)
	err = repo.SoftDeleteByAccountID(context.Background(), tx, "account-001", time.Now())

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
