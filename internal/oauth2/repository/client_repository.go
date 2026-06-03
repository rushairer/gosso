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
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
	Update(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client) error
	SoftDelete(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error
	SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
}
