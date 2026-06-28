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

// clientTestColumns returns the standard column list for oauth2_clients mock rows.
func clientTestColumns() []string {
	return []string{
		"id", "account_id", "client_id", "client_secret_hash",
		"name", "description", "redirect_uris", "post_logout_redirect_uris", "grant_types", "scopes",
		"is_confidential", "metadata",
		"frontchannel_logout_uri", "frontchannel_logout_session_required",
		"backchannel_logout_uri", "backchannel_logout_session_required",
		"created_at", "updated_at", "deleted_at",
	}
}

func setupTestClientService(t *testing.T) (*sql.DB, sqlmock.Sqlmock, OAuth2ClientService) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	clientRepo := repository.NewOAuth2ClientRepository(db)
	svc := NewOAuth2ClientService(db, clientRepo, nil, nil)

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

	rows := sqlmock.NewRows(clientTestColumns()).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, postLogoutURIs, grantTypes, scopes,
		true, nil, "", false, "", false, now, now, nil,
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

	rows := sqlmock.NewRows(clientTestColumns())

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
	updatedAt := now.Add(-1 * time.Hour)

	mock.ExpectBegin()

	// FindByClientIDTx — re-read inside transaction for optimistic locking
	clientRows := sqlmock.NewRows(clientTestColumns()).AddRow(
		"uuid-001", "account-001", "cid-abc", "$2a$10$hash", "Old Name", "",
		[]byte(`["http://localhost/callback"]`), []byte("null"), []byte(`["authorization_code"]`), []byte(`["openid"]`),
		true, []byte("{}"), "", false, "", false, now, updatedAt, nil,
	)
	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("cid-abc").
		WillReturnRows(clientRows)

	// Update with optimistic locking
	mock.ExpectQuery("UPDATE oauth2_clients").
		WithArgs("Updated App", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "uuid-001", updatedAt).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	mock.ExpectCommit()

	client := &domain.OAuth2Client{
		ID:           "uuid-001",
		ClientID:     "cid-abc",
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

	// FindByClientIDTx — client not found
	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("nonexistent-cid").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	client := &domain.OAuth2Client{
		ID:           "nonexistent",
		ClientID:     "nonexistent-cid",
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
	now := time.Now()

	redirectURIs, _ := json.Marshal([]string{"http://localhost/callback"})
	postLogoutURIs, _ := json.Marshal([]string{})
	grantTypes, _ := json.Marshal([]string{domain.GrantTypeAuthorizationCode})
	scopes, _ := json.Marshal([]string{"openid"})

	rows := sqlmock.NewRows(clientTestColumns()).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, postLogoutURIs, grantTypes, scopes,
		true, nil, "", false, "", false, now, now, nil,
	)

	// FindByClientID and SoftDelete now both run inside the same transaction
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("abc123").
		WillReturnRows(rows)
	mock.ExpectExec("UPDATE oauth2_clients SET deleted_at").
		WithArgs(sqlmock.AnyArg(), "uuid-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := svc.DeleteClient(ctx, "account-001", "abc123")
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDeleteClient_NotFound tests deleting a nonexistent client
func TestDeleteClient_NotFound(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()

	// FindByClientID now runs inside the transaction
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("nonexistent").
		WillReturnError(domain.ErrClientNotFound)
	mock.ExpectRollback()

	err := svc.DeleteClient(ctx, "account-001", "nonexistent")
	assert.ErrorIs(t, err, domain.ErrClientNotFound)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDeleteClient_AccessDenied tests deleting a client owned by another account
func TestDeleteClient_AccessDenied(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	redirectURIs, _ := json.Marshal([]string{"http://localhost/callback"})
	postLogoutURIs, _ := json.Marshal([]string{})
	grantTypes, _ := json.Marshal([]string{domain.GrantTypeAuthorizationCode})
	scopes, _ := json.Marshal([]string{"openid"})

	rows := sqlmock.NewRows(clientTestColumns()).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, postLogoutURIs, grantTypes, scopes,
		true, nil, "", false, "", false, now, now, nil,
	)

	// FindByClientID now runs inside the transaction; access denied triggers rollback
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").
		WithArgs("abc123").
		WillReturnRows(rows)
	mock.ExpectRollback()

	err := svc.DeleteClient(ctx, "other-account", "abc123")
	assert.ErrorIs(t, err, ErrClientAccessDenied)

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

func TestRegisterClient_RejectsReservedAdminScopes(t *testing.T) {
	db, _, svc := setupTestClientService(t)
	defer db.Close()

	req := &RegisterClientRequest{
		AccountID:    "account-001",
		Name:         "Escalating App",
		RedirectURIs: []string{"http://localhost/callback"},
		Scopes:       []string{"openid", "admin"},
	}

	client, secret, err := svc.RegisterClient(context.Background(), req)
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "reserved for administrator clients")
}

func TestRegisterClient_AllowsReservedAdminScopesForPrivilegedCaller(t *testing.T) {
	db, mock, svc := setupTestClientService(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO oauth2_clients").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow("client-uuid-admin", now, now))
	mock.ExpectCommit()

	req := &RegisterClientRequest{
		AccountID:           "account-001",
		Name:                "Admin Console",
		RedirectURIs:        []string{"https://admin.example.com/callback"},
		Scopes:              []string{"openid", "admin"},
		AllowReservedScopes: true,
	}

	client, _, err := svc.RegisterClient(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Equal(t, domain.ClientCapabilityAdmin, client.Metadata[domain.ClientCapabilityMetadataKey])
	assert.Equal(t, []string{"openid", "admin"}, client.Scopes)

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

	rows := sqlmock.NewRows(clientTestColumns()).AddRow(
		"uuid-001", "account-001", "abc123", "$2a$10$hash",
		"Test App", "desc", redirectURIs, postLogoutURIs, grantTypes, scopes,
		true, nil, "", false, "", false, now, now, nil,
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
