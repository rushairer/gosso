package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

func TestUpdateSecret(t *testing.T) {
	storageFailure := errors.New("synthetic storage failure")
	for _, kind := range []string{"success", "missing", "concurrent", "storage"} {
		t.Run(kind, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = db.Close() })
			mock.ExpectBegin()
			tx, err := db.Begin()
			require.NoError(t, err)
			client := newTestOAuth2Client()
			expected := time.Now().Add(-time.Hour)
			updated := time.Now()
			query := mock.ExpectQuery("UPDATE oauth2_clients SET client_secret_hash = ").
				WithArgs(client.ClientSecretHash, sqlmock.AnyArg(), client.ID, expected)
			switch kind {
			case "success":
				query.WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(updated))
			case "storage":
				query.WillReturnError(storageFailure)
			default:
				query.WillReturnRows(sqlmock.NewRows([]string{"updated_at"}))
				lookup := mock.ExpectQuery("SELECT (.+) FROM oauth2_clients").WithArgs(client.ClientID)
				if kind == "missing" {
					lookup.WillReturnError(sql.ErrNoRows)
				} else {
					lookup.WillReturnRows(sqlmock.NewRows(clientColumns()).AddRow(clientRowValues(client)...))
				}
			}
			err = NewOAuth2ClientRepository(db).UpdateSecret(context.Background(), tx, client, expected)
			switch kind {
			case "success":
				require.NoError(t, err)
				require.Equal(t, updated, client.UpdatedAt)
			case "missing":
				require.ErrorIs(t, err, domain.ErrClientNotFound)
			case "concurrent":
				require.ErrorIs(t, err, domain.ErrClientConcurrentModification)
			case "storage":
				require.ErrorIs(t, err, storageFailure)
			}
			mock.ExpectRollback()
			require.NoError(t, tx.Rollback())
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
