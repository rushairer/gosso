package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

// OAuth2ClientRepository is the OAuth2 client repository interface
type OAuth2ClientRepository interface {
	Create(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client) error
	FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error)
	FindByClientIDTx(ctx context.Context, tx *sql.Tx, clientID string) (*domain.OAuth2Client, error)
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
	// Update persists changes to an OAuth2 client with optimistic locking.
	// expectedUpdatedAt must match the current row value; returns domain.ErrClientConcurrentModification on mismatch.
	Update(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client, expectedUpdatedAt time.Time) error
	SoftDelete(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error
	SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
	// FindFrontchannelLogoutClientsByAccountID returns clients that have a
	// non-empty frontchannel_logout_uri and a non-deleted consent for the account.
	FindFrontchannelLogoutClientsByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
	// FindBackchannelLogoutClientsByAccountID returns clients that have a
	// non-empty backchannel_logout_uri and a non-deleted consent for the account.
	FindBackchannelLogoutClientsByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
}
