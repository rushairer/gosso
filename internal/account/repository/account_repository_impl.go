package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
	dbPkg "github.com/rushairer/gosso/internal/db"
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

// maxPage prevents integer overflow in offset calculation.
// With MaxPageSize=100, this limits offset to ~2.1 billion which is
// well within int range even on 32-bit platforms.
const maxPage = 21_000_000

// clampPagination normalizes page and pageSize to valid ranges.
// Returns the clamped values and the computed offset.
func clampPagination(page, pageSize int) (int, int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > MaxPageSize {
		pageSize = 20
	}
	if page > maxPage {
		page = maxPage
	}
	offset := (page - 1) * pageSize
	return page, pageSize, offset
}

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

// findAccountByID is a shared helper that queries a single account by ID.
// The includeDeleted flag controls whether soft-deleted rows are included.
func (r *accountRepositoryImpl) findAccountByID(ctx context.Context, q dbPkg.Queryable, accountID string, includeDeleted bool) (*domain.Account, error) {
	query := `
		SELECT id, username, display_name, avatar_url, status, locale, timezone, metadata, created_at, updated_at, deleted_at
		FROM accounts
		WHERE id = $1`
	if !includeDeleted {
		query += " AND deleted_at IS NULL"
	}

	account, err := scanAccount(q.QueryRowContext(ctx, query, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}
	return account, nil
}

// FindByID finds an account by ID (non-deleted only).
func (r *accountRepositoryImpl) FindByID(ctx context.Context, accountID string) (*domain.Account, error) {
	return r.findAccountByID(ctx, r.db, accountID, false)
}

// FindByIDTx finds an account by ID within a transaction (non-deleted only).
func (r *accountRepositoryImpl) FindByIDTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error) {
	return r.findAccountByID(ctx, tx, accountID, false)
}

// FindByIDIncludingDeletedTx finds an account by ID within a transaction, including soft-deleted rows.
func (r *accountRepositoryImpl) FindByIDIncludingDeletedTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Account, error) {
	return r.findAccountByID(ctx, tx, accountID, true)
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

// FindByUsernameWithPasswordCredential finds an account by username and its
// primary password credential in a single JOIN query. Returns
// ErrAccountNotFound if the account does not exist and ErrCredentialNotFound
// if the account has no password credential.
func (r *accountRepositoryImpl) FindByUsernameWithPasswordCredential(ctx context.Context, username string) (*domain.Account, *domain.Credential, error) {
	query := `
		SELECT
			a.id, a.username, a.display_name, a.avatar_url, a.status, a.locale, a.timezone,
			a.metadata, a.created_at, a.updated_at, a.deleted_at,
			c.id, c.account_id, c.credential_type, c.identifier, c.credential_value,
			c.verified, c.primary_credential, c.metadata, c.created_at, c.updated_at,
			c.verified_at, c.last_used_at
		FROM accounts a
		LEFT JOIN account_credentials c
			ON c.account_id = a.id
			AND c.credential_type = $2
			AND c.deleted_at IS NULL
		WHERE a.username = $1 AND a.deleted_at IS NULL
		ORDER BY c.primary_credential DESC NULLS LAST, c.created_at ASC NULLS LAST
		LIMIT 1
	`

	var account domain.Account
	var accountMetadataJSON []byte
	var cred domain.Credential
	var credMetadataJSON []byte
	var credID, credAccountID, credType, credIdentifier, credValue sql.NullString
	var credVerified, credPrimary sql.NullBool
	var credCreatedAt, credUpdatedAt, credVerifiedAt, credLastUsedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, username, domain.CredentialTypePassword).Scan(
		&account.ID,
		&account.Username,
		&account.DisplayName,
		&account.AvatarURL,
		&account.Status,
		&account.Locale,
		&account.Timezone,
		&accountMetadataJSON,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.DeletedAt,
		&credID,
		&credAccountID,
		&credType,
		&credIdentifier,
		&credValue,
		&credVerified,
		&credPrimary,
		&credMetadataJSON,
		&credCreatedAt,
		&credUpdatedAt,
		&credVerifiedAt,
		&credLastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("%w: %s", ErrAccountNotFound, username)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("query account with password credential: %w", err)
	}

	// Parse account metadata
	account.Metadata = make(map[string]any)
	if err := dbPkg.UnmarshalJSONField(accountMetadataJSON, &account.Metadata, "metadata"); err != nil {
		return nil, nil, err
	}

	// If the LEFT JOIN produced no credential row, credID will be NULL.
	if !credID.Valid {
		return &account, nil, fmt.Errorf("%w: account=%s", ErrCredentialNotFound, account.ID)
	}

	// Populate the credential from scanned nullable values.
	cred = domain.Credential{
		ID:                credID.String,
		AccountID:         credAccountID.String,
		Type:              domain.CredentialType(credType.String),
		Value:             credValue.String,
		Verified:          credVerified.Bool,
		PrimaryCredential: credPrimary.Bool,
		CreatedAt:         credCreatedAt.Time,
		UpdatedAt:         credUpdatedAt.Time,
	}
	if credIdentifier.Valid {
		cred.Identifier = &credIdentifier.String
	}
	if credVerifiedAt.Valid {
		cred.VerifiedAt = &credVerifiedAt.Time
	}
	if credLastUsedAt.Valid {
		cred.LastUsedAt = &credLastUsedAt.Time
	}
	cred.Metadata = make(map[string]any)
	if err := dbPkg.UnmarshalJSONField(credMetadataJSON, &cred.Metadata, "metadata"); err != nil {
		return nil, nil, err
	}

	return &account, &cred, nil
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
	page, pageSize, offset := clampPagination(page, pageSize)

	if status != "" && !validStatuses[status] {
		return nil, 0, fmt.Errorf("%w: %q", ErrInvalidStatusFilter, status)
	}

	// Build WHERE clause with consistent parameter numbering.
	// SECURITY: The `where` string is interpolated into the query via fmt.Sprintf.
	// Only append hardcoded SQL fragments and $N placeholders here — never
	// interpolate user-supplied values directly into the where string.
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
	return r.transitionAccountStatus(ctx, tx, accountID, string(domain.AccountStatusActive), string(domain.AccountStatusSuspended))
}

// ActivateAccount atomically sets status to 'active' only if currently 'suspended'.
func (r *accountRepositoryImpl) ActivateAccount(ctx context.Context, tx *sql.Tx, accountID string) error {
	return r.transitionAccountStatus(ctx, tx, accountID, string(domain.AccountStatusSuspended), string(domain.AccountStatusActive))
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
