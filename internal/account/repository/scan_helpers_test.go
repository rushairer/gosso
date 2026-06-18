package repository

import (
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/account/domain"
)

// ──────────────────────────────────────────────
// scanAccount
// ──────────────────────────────────────────────

func TestScanAccount(t *testing.T) {
	tests := []struct {
		name        string
		columns     []string
		rowValues   func() []driver.Value
		wantErr     bool
		wantAccount *domain.Account
	}{
		{
			name: "success",
			columns: []string{
				"id", "username", "display_name", "avatar_url", "status",
				"locale", "timezone", "metadata", "created_at", "updated_at", "deleted_at",
			},
			rowValues: func() []driver.Value {
				username := "testuser"
				avatarURL := "https://example.com/avatar.png"
				createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
				updatedAt := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
				metadata := `{"plan":"pro"}`
				return []driver.Value{
					"account-001", username, "Test User", avatarURL, "active",
					"en", "UTC", metadata, createdAt, updatedAt, nil,
				}
			},
			wantAccount: func() *domain.Account {
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
					Metadata:    map[string]any{"plan": "pro"},
					CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
					UpdatedAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
					DeletedAt:   nil,
				}
			}(),
		},
		{
			name:    "scan error with wrong column count",
			columns: []string{"id", "username"},
			rowValues: func() []driver.Value {
				return []driver.Value{"account-001", "testuser"}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			rows := sqlmock.NewRows(tt.columns).AddRow(tt.rowValues()...)
			mock.ExpectQuery("SELECT").WillReturnRows(rows)

			sqlRows, err := db.Query("SELECT 1")
			require.NoError(t, err)
			require.True(t, sqlRows.Next())

			account, err := scanAccount(sqlRows)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, account)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, account)
			assert.Equal(t, tt.wantAccount.ID, account.ID)
			assert.Equal(t, tt.wantAccount.Username, account.Username)
			assert.Equal(t, tt.wantAccount.DisplayName, account.DisplayName)
			assert.Equal(t, tt.wantAccount.AvatarURL, account.AvatarURL)
			assert.Equal(t, tt.wantAccount.Status, account.Status)
			assert.Equal(t, tt.wantAccount.Locale, account.Locale)
			assert.Equal(t, tt.wantAccount.Timezone, account.Timezone)
			assert.Equal(t, tt.wantAccount.Metadata, account.Metadata)
			assert.Equal(t, tt.wantAccount.CreatedAt, account.CreatedAt)
			assert.Equal(t, tt.wantAccount.UpdatedAt, account.UpdatedAt)
			assert.Nil(t, account.DeletedAt)
		})
	}
}

// ──────────────────────────────────────────────
// scanRole
// ──────────────────────────────────────────────

func TestScanRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	description := "Administrator role"
	createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	permissionsJSON := `["read","write","admin"]`
	metadataJSON := `{"level":5}`

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "permissions", "metadata",
		"created_at", "updated_at", "deleted_at",
	}).AddRow(
		"role-001", "admin", description, permissionsJSON, metadataJSON,
		createdAt, updatedAt, nil,
	)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	sqlRows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	require.True(t, sqlRows.Next())

	role, err := scanRole(sqlRows)
	require.NoError(t, err)
	require.NotNil(t, role)

	assert.Equal(t, "role-001", role.ID)
	assert.Equal(t, "admin", role.Name)
	assert.Equal(t, &description, role.Description)
	assert.Equal(t, []string{"read", "write", "admin"}, role.Permissions)
	assert.Equal(t, map[string]any{"level": float64(5)}, role.Metadata)
	assert.Equal(t, createdAt, role.CreatedAt)
	assert.Equal(t, updatedAt, role.UpdatedAt)
	assert.Nil(t, role.DeletedAt)
}

// ──────────────────────────────────────────────
// scanCredential
// ──────────────────────────────────────────────

func TestScanCredential(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	identifier := "user@example.com"
	createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	verifiedAt := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	lastUsedAt := time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC)
	metadataJSON := `{"source":"signup"}`

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "credential_type", "identifier", "value",
		"verified", "primary_credential", "metadata",
		"created_at", "updated_at", "verified_at", "last_used_at", "deleted_at",
	}).AddRow(
		"cred-001", "account-001", "email", identifier, "hashed-value",
		true, true, metadataJSON,
		createdAt, updatedAt, verifiedAt, lastUsedAt, nil,
	)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	sqlRows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	require.True(t, sqlRows.Next())

	cred, err := scanCredential(sqlRows)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, "cred-001", cred.ID)
	assert.Equal(t, "account-001", cred.AccountID)
	assert.Equal(t, domain.CredentialType("email"), cred.Type)
	assert.Equal(t, &identifier, cred.Identifier)
	assert.Equal(t, "hashed-value", cred.Value)
	assert.True(t, cred.Verified)
	assert.True(t, cred.PrimaryCredential)
	assert.Equal(t, map[string]any{"source": "signup"}, cred.Metadata)
	assert.Equal(t, createdAt, cred.CreatedAt)
	assert.Equal(t, updatedAt, cred.UpdatedAt)
	assert.Equal(t, &verifiedAt, cred.VerifiedAt)
	assert.Equal(t, &lastUsedAt, cred.LastUsedAt)
	assert.Nil(t, cred.DeletedAt)
}

// ──────────────────────────────────────────────
// scanFederatedIdentity
// ──────────────────────────────────────────────

func TestScanFederatedIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	profileJSON := `{"name":"John","avatar":"https://example.com/john.png"}`

	rows := sqlmock.NewRows([]string{
		"id", "account_id", "provider", "provider_user_id", "profile",
		"created_at", "updated_at", "deleted_at",
	}).AddRow(
		"fi-001", "account-001", "google", "google-user-123", profileJSON,
		createdAt, updatedAt, nil,
	)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	sqlRows, err := db.Query("SELECT 1")
	require.NoError(t, err)
	require.True(t, sqlRows.Next())

	identity, err := scanFederatedIdentity(sqlRows)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "fi-001", identity.ID)
	assert.Equal(t, "account-001", identity.AccountID)
	assert.Equal(t, domain.Provider("google"), identity.Provider)
	assert.Equal(t, "google-user-123", identity.ProviderUserID)
	assert.Equal(t, map[string]any{"name": "John", "avatar": "https://example.com/john.png"}, identity.Profile)
	assert.Equal(t, createdAt, identity.CreatedAt)
	assert.Equal(t, updatedAt, identity.UpdatedAt)
	assert.Nil(t, identity.DeletedAt)
}
