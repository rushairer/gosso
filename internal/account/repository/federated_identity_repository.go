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
	ErrFederatedIdentityNotFound = errors.New("federated identity not found")
)

// FederatedIdentityRepository defines the interface for federated identity repository
type FederatedIdentityRepository interface {
	// CreateFederatedIdentity creates a federated identity (requires transaction)
	CreateFederatedIdentity(ctx context.Context, tx *sql.Tx, identity *domain.FederatedIdentity) error

	// FindByProvider finds a federated identity by provider and provider user ID
	FindByProvider(ctx context.Context, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error)

	// FindByProviderTx finds a federated identity by provider and provider user ID within a transaction.
	// Use this variant inside RunInTransaction to avoid TOCTOU race conditions.
	FindByProviderTx(ctx context.Context, tx *sql.Tx, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error)

	// FindByAccountID finds all federated identities by account ID
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.FederatedIdentity, error)

	// FindByAccountIDTx finds all federated identities by account ID within a transaction.
	// Use this variant inside RunInTransaction to avoid TOCTOU race conditions.
	FindByAccountIDTx(ctx context.Context, tx *sql.Tx, accountID string) ([]*domain.FederatedIdentity, error)

	// SoftDeleteByAccountID soft deletes all federated identities of an account (requires transaction)
	SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error

	// SoftDeleteByID soft deletes a single federated identity (requires transaction).
	// accountID enforces ownership: only the identity's owner can delete it.
	SoftDeleteByID(ctx context.Context, tx *sql.Tx, accountID, identityID string, deletedAt time.Time) error
}
