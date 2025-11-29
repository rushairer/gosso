package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

// AccountRepository 账号仓储接口
type AccountRepository interface {
	// CreateAccount 创建账号（需要事务）
	CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error

	// FindByID 根据 ID 查找账号
	FindByID(ctx context.Context, accountID string) (*domain.Account, error)

	// FindByUsername 根据用户名查找账号
	FindByUsername(ctx context.Context, username string) (*domain.Account, error)

	// UpdateAccount 更新账号（需要事务）
	UpdateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error

	// SoftDeleteAccount 软删除账号（需要事务）
	SoftDeleteAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
}

// accountRepositoryImpl 账号仓储实现
type accountRepositoryImpl struct {
	db *sql.DB
}

// NewAccountRepository 创建账号仓储
func NewAccountRepository(db *sql.DB) AccountRepository {
	return &accountRepositoryImpl{db: db}
}

// CreateAccount 创建账号
func (r *accountRepositoryImpl) CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error {
	query := `
		INSERT INTO accounts (id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	metadataJSON, err := json.Marshal(account.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		account.ID,
		account.Username,
		account.DisplayName,
		account.AvatarURL,
		account.Status,
		account.Locale,
		account.Timezone,
		metadataJSON,
		account.CreatedAt,
		account.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert account: %w", err)
	}

	return nil
}

// FindByID 根据 ID 查找账号
func (r *accountRepositoryImpl) FindByID(ctx context.Context, accountID string) (*domain.Account, error) {
	query := `
		SELECT id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at, deleted_at
		FROM accounts
		WHERE id = $1 AND deleted_at IS NULL
	`

	account := &domain.Account{}
	var metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, accountID).Scan(
		&account.ID,
		&account.Username,
		&account.DisplayName,
		&account.AvatarURL,
		&account.Status,
		&account.Locale,
		&account.Timezone,
		&metadataJSON,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account not found: %s", accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	// 解析 metadata
	if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return account, nil
}

// FindByUsername 根据用户名查找账号
func (r *accountRepositoryImpl) FindByUsername(ctx context.Context, username string) (*domain.Account, error) {
	query := `
		SELECT id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at, deleted_at
		FROM accounts
		WHERE username = $1 AND deleted_at IS NULL
	`

	account := &domain.Account{}
	var metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&account.ID,
		&account.Username,
		&account.DisplayName,
		&account.AvatarURL,
		&account.Status,
		&account.Locale,
		&account.Timezone,
		&metadataJSON,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account not found with username: %s", username)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	// 解析 metadata
	if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return account, nil
}

// UpdateAccount 更新账号
func (r *accountRepositoryImpl) UpdateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error {
	query := `
		UPDATE accounts
		SET username = $1, display_name = $2, avatar_url = $3, status = $4,
		    locale = $5, timezone = $6, metadata = $7, updated_at = $8
		WHERE id = $9 AND deleted_at IS NULL
	`

	metadataJSON, err := json.Marshal(account.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	result, err := tx.ExecContext(ctx, query,
		account.Username,
		account.DisplayName,
		account.AvatarURL,
		account.Status,
		account.Locale,
		account.Timezone,
		metadataJSON,
		time.Now(),
		account.ID,
	)
	if err != nil {
		return fmt.Errorf("update account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("account not found or already deleted: %s", account.ID)
	}

	return nil
}

// SoftDeleteAccount 软删除账号
func (r *accountRepositoryImpl) SoftDeleteAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `
		UPDATE accounts
		SET deleted_at = $1, updated_at = $1, status = 'deleted'
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, accountID)
	if err != nil {
		return fmt.Errorf("soft delete account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("account not found or already deleted: %s", accountID)
	}

	return nil
}
