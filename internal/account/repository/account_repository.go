package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

// Sentinel errors for repository operations
var (
	ErrAccountNotFound         = errors.New("account not found")
	ErrInvalidStatusTransition = errors.New("invalid account status transition")
)

// AccountRepository defines the interface for account repository
type AccountRepository interface {
	// CreateAccount creates a new account (requires transaction)
	CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error

	// FindByID finds an account by ID
	FindByID(ctx context.Context, accountID string) (*domain.Account, error)

	// FindByIDTx finds an account by ID within a transaction (for transactional reads).
	// Use this when the read must participate in the same transaction snapshot as writes.
	FindByIDTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error)

	// FindByUsername finds an account by username
	FindByUsername(ctx context.Context, username string) (*domain.Account, error)

	// UpdateAccount updates an account (requires transaction)
	UpdateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error

	// SoftDeleteAccount soft deletes an account (requires transaction)
	SoftDeleteAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error

	// FindAll queries accounts with pagination (for admin search)
	FindAll(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error)

	// SuspendAccount atomically sets status to 'suspended' only if currently 'active'.
	// Returns ErrInvalidStatusTransition if the account doesn't exist or is not in 'active' status.
	SuspendAccount(ctx context.Context, tx *sql.Tx, accountID string) error

	// ActivateAccount atomically sets status to 'active' only if currently 'suspended'.
	// Returns ErrInvalidStatusTransition if the account doesn't exist or is not in 'suspended' status.
	ActivateAccount(ctx context.Context, tx *sql.Tx, accountID string) error
}
