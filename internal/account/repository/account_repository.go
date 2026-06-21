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
	ErrConcurrentModification  = errors.New("account was modified concurrently")
	ErrInvalidStatusFilter     = errors.New("invalid status filter")
)

// AccountRepository defines the interface for account repository
type AccountRepository interface {
	// CreateAccount creates a new account (requires transaction)
	CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error

	// FindByID finds an account by ID
	FindByID(ctx context.Context, accountID string) (*domain.Account, error)

	// FindByIDTx finds an account by ID within a transaction (non-deleted only).
	// Use this when you need to read account data inside an existing transaction,
	// e.g., for optimistic locking before an update.
	FindByIDTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error)

	// FindByIDIncludingDeletedTx finds an account by ID within a transaction,
	// including soft-deleted rows. Use this for idempotency checks in
	// soft-delete flows where the caller must distinguish "not found" from
	// "already deleted". Prefer FindByID for normal reads.
	FindByIDIncludingDeletedTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error)

	// FindByUsername finds an account by username
	FindByUsername(ctx context.Context, username string) (*domain.Account, error)

	// FindByUsernameWithPasswordCredential finds an account by username and its
	// primary password credential in a single JOIN query. Returns
	// ErrAccountNotFound if the account does not exist and
	// ErrCredentialNotFound if the account has no password credential.
	// This is an optimisation for the login hot path: it eliminates one
	// DB round-trip compared to calling FindByUsername + FindPasswordCredential
	// sequentially.
	FindByUsernameWithPasswordCredential(ctx context.Context, username string) (*domain.Account, *domain.Credential, error)

	// UpdateAccount updates an account with optimistic locking.
	// expectedUpdatedAt is the value of updated_at that was read earlier in the same
	// transaction; the UPDATE will only succeed if the row still matches.
	// Returns ErrConcurrentModification if another writer changed the row,
	// or ErrAccountNotFound if the row no longer exists.
	UpdateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account, expectedUpdatedAt time.Time) error

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
