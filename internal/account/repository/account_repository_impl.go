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

// accountRepositoryImpl implements AccountRepository
type accountRepositoryImpl struct {
	db *sql.DB
}

// NewAccountRepository creates a new account repository
func NewAccountRepository(db *sql.DB) AccountRepository {
	return &accountRepositoryImpl{db: db}
}

// MaxPageSize is the upper bound for pagination page size.
const MaxPageSize = 100

// validStatuses is a whitelist of allowed status values for FindAll filtering.
var validStatuses = map[string]bool{
	string(domain.AccountStatusActive):    true,
	string(domain.AccountStatusSuspended): true,
	string(domain.AccountStatusDeleted):   true,
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

	account, err := scanAccount(r.db.QueryRowContext(ctx, query, accountID))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	return account, nil
}

// FindByIDTx finds an account by ID within a transaction (non-deleted only).
func (r *accountRepositoryImpl) FindByIDTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error) {
	query := `
		SELECT id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at, deleted_at
		FROM accounts
		WHERE id = $1 AND deleted_at IS NULL
	`

	account, err := scanAccount(tx.QueryRowContext(ctx, query, accountID))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	return account, nil
}

// FindByIDIncludingDeletedTx finds an account by ID within a transaction, including soft-deleted rows.
func (r *accountRepositoryImpl) FindByIDIncludingDeletedTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error) {
	query := `
		SELECT id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at, deleted_at
		FROM accounts
		WHERE id = $1 -- intentionally includes soft-deleted rows
	`

	account, err := scanAccount(tx.QueryRowContext(ctx, query, accountID))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
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

	account, err := scanAccount(r.db.QueryRowContext(ctx, query, username))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, username)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}

	return account, nil
}

// UpdateAccount updates an account with optimistic locking.
func (r *accountRepositoryImpl) UpdateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account, expectedUpdatedAt time.Time) error {
	query := `
		UPDATE accounts
		SET username = $1, display_name = $2, avatar_url = $3, status = $4,
		    locale = $5, timezone = $6, metadata = $7, updated_at = $8
		WHERE id = $9 AND deleted_at IS NULL AND updated_at = $10
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
		account.UpdatedAt,
		account.ID,
		expectedUpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		// Distinguish "not found" from "concurrent modification"
		_, findErr := r.FindByIDTx(ctx, tx, account.ID)
		if findErr != nil {
			return findErr // ErrAccountNotFound
		}
		return fmt.Errorf("%w: %s", ErrConcurrentModification, account.ID)
	}

	return nil
}

// SoftDeleteAccount soft deletes an account
func (r *accountRepositoryImpl) SoftDeleteAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `
		UPDATE accounts
		SET deleted_at = $1, updated_at = $1, status = $2
		WHERE id = $3 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, string(domain.AccountStatusDeleted), accountID)
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

// FindAll queries accounts with pagination
func (r *accountRepositoryImpl) FindAll(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > MaxPageSize {
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
	args = append(args, pageSize, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	accounts, err := scanAccounts(rows)
	if err != nil {
		return nil, 0, err
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
