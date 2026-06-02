package service

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
	"github.com/rushairer/gosso/internal/oauth2/repository"
)

func setupTestClientService(t *testing.T) (*sql.DB, sqlmock.Sqlmock, OAuth2ClientService) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	clientRepo := repository.NewOAuth2ClientRepository(db)
	svc := NewOAuth2ClientService(db, clientRepo)

	return db, mock, svc
}

func TestRegisterClient(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	// ExpectBegin + INSERT ... RETURNING + ExpectCommit
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO oauth2_clients").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow("client-uuid-001", now, now))
	mock.ExpectCommit()

	req := &RegisterClientRequest{
		AccountID:      "account-001",
		Name:           "Test App",
		Description:    "A test application",
		RedirectURIs:   []string{"http://localhost/callback"},
		GrantTypes:     []string{domain.GrantTypeAuthorizationCode},
		Scopes:         []string{"openid", "profile"},
		IsConfidential: true,
	}

	client, secret, err := svc.RegisterClient(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.NotEmpty(t, secret) // confidential client gets a secret
	assert.Equal(t, "account-001", client.AccountID)
	assert.Equal(t, "Test App", client.Name)
	assert.NotEmpty(t, client.ClientID)
	assert.NotEmpty(t, client.ClientSecretHash)
	assert.True(t, client.IsConfidential)
	assert.Equal(t, []string{"http://localhost/callback"}, client.RedirectURIs)
	assert.Equal(t, []string{domain.GrantTypeAuthorizationCode}, client.GrantTypes)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterClient_Public(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO oauth2_clients").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow("client-uuid-002", now, now))
	mock.ExpectCommit()

	req := &RegisterClientRequest{
		AccountID:      "account-002",
		Name:           "Public App",
		RedirectURIs:   []string{"http://localhost/callback"},
		IsConfidential: false,
	}

	client, secret, err := svc.RegisterClient(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Empty(t, secret) // public client gets no secret
	assert.False(t, client.IsConfidential)
	assert.Equal(t, []string{domain.GrantTypeAuthorizationCode}, client.GrantTypes) // default
	assert.Equal(t, []string{"openid"}, client.Scopes)                              // default

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFindByClientID(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	redirectURIs, _ := json.Marshal([]string{"http://localhost/callback"})
	grantTypes, _ := json.Marshal([]string{domain.GrantTypeAuthorizationCode})
	scopes, _ := json.Marshal([]string{"openid"})

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "client_id", "client_secret_hash",
		"name", "description", "redirect_uris", "grant_types", "scopes",
		"is_confidential", "metadata", "created_at", "updated_at",
	}).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, grantTypes, scopes,
		true, nil, now, now,
	)

	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("abc123").
		WillReturnRows(rows)

	client, err := svc.FindByClientID(ctx, "abc123")
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "abc123", client.ClientID)
	assert.Equal(t, "account-001", client.AccountID)
	assert.Equal(t, "Test App", client.Name)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFindByClientID_NotFound(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()

	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	client, err := svc.FindByClientID(ctx, "nonexistent")
	assert.ErrorIs(t, err, domain.ErrClientNotFound)
	assert.Nil(t, client)

	assert.NoError(t, mock.ExpectationsWereMet())
}
