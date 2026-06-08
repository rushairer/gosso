package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// TestFindByAccountID tests finding clients by account ID
func TestFindByAccountID(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	redirectURIs, _ := json.Marshal([]string{"http://localhost/callback"})
	postLogoutURIs, _ := json.Marshal([]string{})
	grantTypes, _ := json.Marshal([]string{domain.GrantTypeAuthorizationCode})
	scopes, _ := json.Marshal([]string{"openid"})

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "client_id", "client_secret_hash",
		"name", "description", "redirect_uris", "post_logout_redirect_uris", "grant_types", "scopes",
		"is_confidential", "metadata", "created_at", "updated_at",
	}).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, postLogoutURIs, grantTypes, scopes,
		true, nil, now, now,
	)

	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("account-001").
		WillReturnRows(rows)

	clients, err := svc.FindByAccountID(ctx, "account-001")
	require.NoError(t, err)
	assert.Len(t, clients, 1)
	assert.Equal(t, "abc123", clients[0].ClientID)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestFindByAccountID_Empty tests finding clients when account has none
func TestFindByAccountID_Empty(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "client_id", "client_secret_hash",
		"name", "description", "redirect_uris", "post_logout_redirect_uris", "grant_types", "scopes",
		"is_confidential", "metadata", "created_at", "updated_at",
	})

	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("account-001").
		WillReturnRows(rows)

	clients, err := svc.FindByAccountID(ctx, "account-001")
	require.NoError(t, err)
	assert.Len(t, clients, 0)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUpdateClient tests updating an OAuth2 client
func TestUpdateClient(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE oauth2_clients").
		WithArgs("Updated App", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "uuid-001").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	mock.ExpectCommit()

	client := &domain.OAuth2Client{
		ID:           "uuid-001",
		Name:         "Updated App",
		RedirectURIs: []string{"http://localhost/callback"},
		GrantTypes:   []string{domain.GrantTypeAuthorizationCode},
		Scopes:       []string{"openid"},
	}

	err := svc.UpdateClient(ctx, client)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUpdateClient_NotFound tests updating a nonexistent client
func TestUpdateClient_NotFound(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE oauth2_clients").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	client := &domain.OAuth2Client{
		ID:           "nonexistent",
		Name:         "Updated App",
		RedirectURIs: []string{"http://localhost/callback"},
		GrantTypes:   []string{domain.GrantTypeAuthorizationCode},
		Scopes:       []string{"openid"},
	}

	err := svc.UpdateClient(ctx, client)
	assert.ErrorIs(t, err, domain.ErrClientNotFound)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDeleteClient tests deleting an OAuth2 client
func TestDeleteClient(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oauth2_clients SET deleted_at").
		WithArgs(sqlmock.AnyArg(), "uuid-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := svc.DeleteClient(ctx, "uuid-001")
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDeleteClient_NotFound tests deleting a nonexistent client
func TestDeleteClient_NotFound(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oauth2_clients SET deleted_at").
		WithArgs(sqlmock.AnyArg(), "nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := svc.DeleteClient(ctx, "nonexistent")
	assert.ErrorIs(t, err, domain.ErrClientNotFound)

	assert.NoError(t, mock.ExpectationsWereMet())
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
	postLogoutURIs, _ := json.Marshal([]string{})
	grantTypes, _ := json.Marshal([]string{domain.GrantTypeAuthorizationCode})
	scopes, _ := json.Marshal([]string{"openid"})

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "client_id", "client_secret_hash",
		"name", "description", "redirect_uris", "post_logout_redirect_uris", "grant_types", "scopes",
		"is_confidential", "metadata", "created_at", "updated_at",
	}).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, postLogoutURIs, grantTypes, scopes,
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

func TestRegisterClient_DBError(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	mock.ExpectBegin().WillReturnError(fmt.Errorf("db unavailable"))

	req := &RegisterClientRequest{
		AccountID: "account-001",
		Name:      "Test App",
	}
	_, _, err := svc.RegisterClient(ctx, req)
	assert.Error(t, err)
}
