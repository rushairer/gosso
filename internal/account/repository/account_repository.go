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

// Sentinel errors for repository operations
var (
	ErrAccountNotFound       = errors.New("account not found")
	ErrInvalidStatusTransition = errors.New("invalid account status transition")
)

// AccountRepository defines the interface for account repository
type AccountRepository interface {
	// CreateAccount creates a new account (requires transaction)
	CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error

	// FindByID finds an account by ID
	FindByID(ctx context.Context, accountID string) (*domain.Account, error)

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

// accountRepositoryImpl implements AccountRepository
type accountRepositoryImpl struct {
	db *sql.DB
}

// NewAccountRepository creates a new account repository
func NewAccountRepository(db *sql.DB) AccountRepository {
	return &accountRepositoryImpl{db: db}
}

// CreateAccount creates a new account
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

// FindByID finds an account by ID
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

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	// Parse metadata
	if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return account, nil
}

// FindByUsername finds an account by username
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

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, username)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	// Parse metadata
	if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return account, nil
}

// UpdateAccount updates an account
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
		return fmt.Errorf("%w: %s", ErrAccountNotFound, account.ID)
	}

	return nil
}

// SoftDeleteAccount soft deletes an account
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
		return fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}

	return nil
}

// validStatuses is a whitelist of allowed status values for FindAll filtering.
var validStatuses = map[string]bool{
	string(domain.AccountStatusActive):    true,
	string(domain.AccountStatusSuspended): true,
	string(domain.AccountStatusDeleted):   true,
}

// FindAll queries accounts with pagination
func (r *accountRepositoryImpl) FindAll(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	if status != "" && !validStatuses[status] {
		return nil, 0, fmt.Errorf("invalid status filter: %q", status)
	}

	// Build WHERE clause with consistent parameter numbering
	where := "deleted_at IS NULL"
	args := []interface{}{}
	paramIdx := 1
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", paramIdx)
		args = append(args, status)
		paramIdx++
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM accounts WHERE %s", where)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count accounts: %w", err)
	}

	if total == 0 {
		return []*domain.Account{}, 0, nil
	}

	// Select with LIMIT and OFFSET appended after WHERE params
	selectQuery := fmt.Sprintf(`
			SELECT id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at, deleted_at
			FROM accounts
			WHERE %s
			ORDER BY created_at DESC
			LIMIT $%d OFFSET $%d`, where, paramIdx, paramIdx+1)
	selectArgs := append(args, pageSize, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var accounts []*domain.Account
	for rows.Next() {
		account := &domain.Account{}
		var metadataJSON []byte
		if err := rows.Scan(
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
		); err != nil {
			return nil, 0, fmt.Errorf("scan account: %w", err)
		}
		if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
			return nil, 0, fmt.Errorf("unmarshal metadata: %w", err)
		}
		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate accounts: %w", err)
	}

	return accounts, total, nil
}

// SuspendAccount atomically sets status to 'suspended' only if currently 'active'.
func (r *accountRepositoryImpl) SuspendAccount(ctx context.Context, tx *sql.Tx, accountID string) error {
	return r.transitionAccountStatus(ctx, tx, accountID, "active", "suspended")
}

// ActivateAccount atomically sets status to 'active' only if currently 'suspended'.
func (r *accountRepositoryImpl) ActivateAccount(ctx context.Context, tx *sql.Tx, accountID string) error {
	return r.transitionAccountStatus(ctx, tx, accountID, "suspended", "active")
}

// transitionAccountStatus is a shared helper for status transitions.
func (r *accountRepositoryImpl) transitionAccountStatus(ctx context.Context, tx *sql.Tx, accountID, fromStatus, toStatus string) error {
	query := `UPDATE accounts SET status = $3, updated_at = $1
		WHERE id = $2 AND status = $4 AND deleted_at IS NULL`
	result, err := tx.ExecContext(ctx, query, time.Now(), accountID, toStatus, fromStatus)
	if err != nil {
		return fmt.Errorf("%s account: %w", toStatus, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: account %s not found or not in %s status", ErrInvalidStatusTransition, accountID, fromStatus)
	}
	return nil
}
