package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

type federatedIdentityRepositoryImpl struct {
	db *sql.DB
}

const federatedIdentityByProviderQuery = `
	SELECT id, account_id, provider, provider_user_id, profile, created_at, updated_at, deleted_at
	FROM federated_identities
	WHERE provider = $1 AND provider_user_id = $2 AND deleted_at IS NULL
	LIMIT 1
`

// NewFederatedIdentityRepository creates a new federated identity repository
func NewFederatedIdentityRepository(db *sql.DB) FederatedIdentityRepository {
	return &federatedIdentityRepositoryImpl{db: db}
}

// CreateFederatedIdentity creates a federated identity
func (r *federatedIdentityRepositoryImpl) CreateFederatedIdentity(ctx context.Context, tx *sql.Tx, identity *domain.FederatedIdentity) error {
	query := `
		INSERT INTO federated_identities (id, account_id, provider, provider_user_id, profile, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	profileJSON, err := json.Marshal(identity.Profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		identity.ID,
		identity.AccountID,
		identity.Provider,
		identity.ProviderUserID,
		profileJSON,
		identity.CreatedAt,
		identity.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert federated identity: %w", err)
	}

	return nil
}

// FindByProvider finds a federated identity by provider and provider user ID
func (r *federatedIdentityRepositoryImpl) FindByProvider(ctx context.Context, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error) {
	return findFederatedIdentityByProvider(ctx, r.db.QueryRowContext, provider, providerUserID)
}

// FindByProviderTx finds a federated identity by provider and provider user ID within a transaction.
func (r *federatedIdentityRepositoryImpl) FindByProviderTx(ctx context.Context, tx *sql.Tx, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error) {
	return findFederatedIdentityByProvider(ctx, tx.QueryRowContext, provider, providerUserID)
}

// findFederatedIdentityByProvider is the shared implementation for both transactional and non-transactional variants.
func findFederatedIdentityByProvider(ctx context.Context, queryRow func(context.Context, string, ...any) *sql.Row, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error) {
	identity, err := scanFederatedIdentity(queryRow(ctx, federatedIdentityByProviderQuery, provider, providerUserID))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s/%s", ErrFederatedIdentityNotFound, provider, providerUserID)
	}
	if err != nil {
		return nil, fmt.Errorf("query federated identity: %w", err)
	}

	return identity, nil
}

// FindByAccountID finds all federated identities by account ID
func (r *federatedIdentityRepositoryImpl) FindByAccountID(ctx context.Context, accountID string) ([]*domain.FederatedIdentity, error) {
	query := `
		SELECT id, account_id, provider, provider_user_id, profile, created_at, updated_at, deleted_at
		FROM federated_identities
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("query federated identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	identities, err := scanFederatedIdentities(rows)
	if err != nil {
		return nil, err
	}

	return identities, nil
}

// FindByAccountIDTx finds all federated identities by account ID within a transaction.
func (r *federatedIdentityRepositoryImpl) FindByAccountIDTx(ctx context.Context, tx *sql.Tx, accountID string) ([]*domain.FederatedIdentity, error) {
	query := `
		SELECT id, account_id, provider, provider_user_id, profile, created_at, updated_at, deleted_at
		FROM federated_identities
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`

	rows, err := tx.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("query federated identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	identities, err := scanFederatedIdentities(rows)
	if err != nil {
		return nil, err
	}

	return identities, nil
}

// SoftDeleteByAccountID soft deletes all federated identities of an account.
// Returns nil even if zero rows are affected (idempotent for bulk delete).
func (r *federatedIdentityRepositoryImpl) SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `
		UPDATE federated_identities
		SET deleted_at = $1, updated_at = $1
		WHERE account_id = $2 AND deleted_at IS NULL
	`

	_, err := tx.ExecContext(ctx, query, deletedAt, accountID)
	if err != nil {
		return fmt.Errorf("soft delete federated identities: %w", err)
	}

	return nil
}

// SoftDeleteByID soft deletes a single federated identity
func (r *federatedIdentityRepositoryImpl) SoftDeleteByID(ctx context.Context, tx *sql.Tx, accountID, identityID string, deletedAt time.Time) error {
	query := `
		UPDATE federated_identities
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND account_id = $3 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, identityID, accountID)
	if err != nil {
		return fmt.Errorf("soft delete federated identity: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrFederatedIdentityNotFound, identityID)
	}

	return nil
}
