package repository

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

// ──────────────────────────────────────────────
// scanOAuth2Client
// ──────────────────────────────────────────────

func TestScanOAuth2Client_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	redirectURIs := []string{"https://app.example.com/callback"}
	postLogoutURIs := []string{"https://app.example.com/logout"}
	grantTypes := []string{"authorization_code", "refresh_token"}
	scopes := []string{"openid", "profile"}
	metadata := map[string]any{"key": "value"}

	ruJSON, _ := json.Marshal(redirectURIs)
	pluJSON, _ := json.Marshal(postLogoutURIs)
	gtJSON, _ := json.Marshal(grantTypes)
	scJSON, _ := json.Marshal(scopes)
	mdJSON, _ := json.Marshal(metadata)

	columns := clientColumns()
	rows := sqlmock.NewRows(columns).AddRow(
		"client-uuid-001", "account-001", "cid-abc123", "$2a$10$hash",
		"Test App", "A test app",
		ruJSON, pluJSON, gtJSON, scJSON,
		true, mdJSON, "", false, "", false,
		now, now, nil,
	)
	mock.ExpectQuery("SELECT .+ FROM oauth2_clients").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM oauth2_clients")
	require.NoError(t, err)
	require.True(t, result.Next())

	client, err := scanOAuth2Client(result)
	require.NoError(t, err)

	// 18 columns scanned (15 original + 4 new logout URI columns - 1 for deleted_at which is nil)
	assert.Equal(t, "client-uuid-001", client.ID)
	assert.Equal(t, "account-001", client.AccountID)
	assert.Equal(t, "cid-abc123", client.ClientID)
	assert.Equal(t, "$2a$10$hash", client.ClientSecretHash)
	assert.Equal(t, "Test App", client.Name)
	assert.Equal(t, "A test app", client.Description)
	assert.True(t, client.IsConfidential)

	// 5 JSON fields unmarshaled
	assert.Equal(t, redirectURIs, client.RedirectURIs)
	assert.Equal(t, postLogoutURIs, client.PostLogoutRedirectURIs)
	assert.Equal(t, grantTypes, client.GrantTypes)
	assert.Equal(t, scopes, client.Scopes)
	assert.Equal(t, "value", client.Metadata["key"])

	assert.False(t, client.CreatedAt.IsZero())
	assert.False(t, client.UpdatedAt.IsZero())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestScanOAuth2Client_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Return a row with wrong number of columns to trigger a scan error
	rows := sqlmock.NewRows([]string{"id"}).AddRow("only-one-col")
	mock.ExpectQuery("SELECT .+ FROM oauth2_clients").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM oauth2_clients")
	require.NoError(t, err)
	require.True(t, result.Next())

	client, err := scanOAuth2Client(result)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// scanConsent
// ──────────────────────────────────────────────

func TestScanConsent_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	scopes := []string{"openid", "email"}
	scJSON, _ := json.Marshal(scopes)

	columns := []string{"id", "account_id", "client_id", "scopes", "granted_at", "created_at", "updated_at", "deleted_at"}
	rows := sqlmock.NewRows(columns).AddRow(
		"consent-001", "account-001", "client-001",
		scJSON, now, now, now, nil,
	)
	mock.ExpectQuery("SELECT .+ FROM oauth2_consents").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM oauth2_consents")
	require.NoError(t, err)
	require.True(t, result.Next())

	consent, err := scanConsent(result)
	require.NoError(t, err)

	// 7 columns scanned
	assert.Equal(t, "consent-001", consent.ID)
	assert.Equal(t, "account-001", consent.AccountID)
	assert.Equal(t, "client-001", consent.ClientID)
	assert.Equal(t, scopes, consent.Scopes)
	assert.False(t, consent.GrantedAt.IsZero())
	assert.False(t, consent.CreatedAt.IsZero())
	assert.False(t, consent.UpdatedAt.IsZero())
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// scanOAuth2Clients (plural)
// ──────────────────────────────────────────────

func TestScanOAuth2Clients_MultipleRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	c1 := &domain.OAuth2Client{ID: "c1", AccountID: "a1", ClientID: "cid1", Name: "App1", GrantTypes: []string{"code"}, Scopes: []string{"openid"}}
	c2 := &domain.OAuth2Client{ID: "c2", AccountID: "a2", ClientID: "cid2", Name: "App2", GrantTypes: []string{"implicit"}, Scopes: []string{"profile"}}

	rows := sqlmock.NewRows(clientColumns()).
		AddRow(c1.ID, c1.AccountID, c1.ClientID, "", c1.Name, "",
			mustMarshal(t, c1.RedirectURIs), mustMarshal(t, c1.PostLogoutRedirectURIs),
			mustMarshal(t, c1.GrantTypes), mustMarshal(t, c1.Scopes),
			false, nil, "", false, "", false,
			now, now, nil).
		AddRow(c2.ID, c2.AccountID, c2.ClientID, "", c2.Name, "",
			mustMarshal(t, c2.RedirectURIs), mustMarshal(t, c2.PostLogoutRedirectURIs),
			mustMarshal(t, c2.GrantTypes), mustMarshal(t, c2.Scopes),
			false, nil, "", false, "", false,
			now, now, nil)
	mock.ExpectQuery("SELECT .+ FROM oauth2_clients").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM oauth2_clients")
	require.NoError(t, err)

	clients, err := scanOAuth2Clients(result)
	require.NoError(t, err)
	require.Len(t, clients, 2)
	assert.Equal(t, "c1", clients[0].ID)
	assert.Equal(t, "c2", clients[1].ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func mustMarshal(t *testing.T, v any) driver.Value {
	t.Helper()
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
