package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

// FederatedIdentityRepository 第三方身份仓储接口
type FederatedIdentityRepository interface {
	// CreateFederatedIdentity 创建第三方身份（需要事务）
	CreateFederatedIdentity(ctx context.Context, tx *sql.Tx, identity *domain.FederatedIdentity) error

	// FindByProvider 根据提供商和提供商用户 ID 查找
	FindByProvider(ctx context.Context, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error)

	// FindByAccountID 根据账号 ID 查找所有第三方身份
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.FederatedIdentity, error)

	// SoftDeleteByAccountID 软删除账号的所有第三方身份（需要事务）
	SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error

	// SoftDeleteByID 软删除单个第三方身份（需要事务）
	SoftDeleteByID(ctx context.Context, tx *sql.Tx, identityID string, deletedAt time.Time) error
}

type federatedIdentityRepositoryImpl struct {
	db *sql.DB
}

// NewFederatedIdentityRepository 创建第三方身份仓储
func NewFederatedIdentityRepository(db *sql.DB) FederatedIdentityRepository {
	return &federatedIdentityRepositoryImpl{db: db}
}

// CreateFederatedIdentity 创建第三方身份
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

// FindByProvider 根据提供商和提供商用户 ID 查找
func (r *federatedIdentityRepositoryImpl) FindByProvider(ctx context.Context, provider domain.Provider, providerUserID string) (*domain.FederatedIdentity, error) {
	query := `
		SELECT id, account_id, provider, provider_user_id, profile, created_at, updated_at, deleted_at
		FROM federated_identities
		WHERE provider = $1 AND provider_user_id = $2 AND deleted_at IS NULL
		LIMIT 1
	`

	identity := &domain.FederatedIdentity{}
	var profileJSON []byte

	err := r.db.QueryRowContext(ctx, query, provider, providerUserID).Scan(
		&identity.ID,
		&identity.AccountID,
		&identity.Provider,
		&identity.ProviderUserID,
		&profileJSON,
		&identity.CreatedAt,
		&identity.UpdatedAt,
		&identity.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("federated identity not found: %s/%s", provider, providerUserID)
	}
	if err != nil {
		return nil, fmt.Errorf("query federated identity: %w", err)
	}

	if err := json.Unmarshal(profileJSON, &identity.Profile); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}

	return identity, nil
}

// FindByAccountID 根据账号 ID 查找所有第三方身份
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
	defer rows.Close()

	var identities []*domain.FederatedIdentity
	for rows.Next() {
		identity := &domain.FederatedIdentity{}
		var profileJSON []byte

		err := rows.Scan(
			&identity.ID,
			&identity.AccountID,
			&identity.Provider,
			&identity.ProviderUserID,
			&profileJSON,
			&identity.CreatedAt,
			&identity.UpdatedAt,
			&identity.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan federated identity: %w", err)
		}

		if err := json.Unmarshal(profileJSON, &identity.Profile); err != nil {
			return nil, fmt.Errorf("unmarshal profile: %w", err)
		}

		identities = append(identities, identity)
	}

	return identities, nil
}

// SoftDeleteByAccountID 软删除账号的所有第三方身份
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

// SoftDeleteByID 软删除单个第三方身份
func (r *federatedIdentityRepositoryImpl) SoftDeleteByID(ctx context.Context, tx *sql.Tx, identityID string, deletedAt time.Time) error {
	query := `
		UPDATE federated_identities
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, identityID)
	if err != nil {
		return fmt.Errorf("soft delete federated identity: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("federated identity not found or already deleted: %s", identityID)
	}

	return nil
}
