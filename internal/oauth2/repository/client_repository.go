package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

// OAuth2ClientRepository OAuth2 客户端仓储接口
type OAuth2ClientRepository interface {
	Create(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client) error
	FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error)
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
	Update(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client) error
	SoftDelete(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error
}
