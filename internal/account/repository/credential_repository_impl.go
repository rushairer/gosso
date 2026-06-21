package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

type credentialRepositoryImpl struct {
	db *sql.DB
}

// NewCredentialRepository creates a new credential repository
func NewCredentialRepository(db *sql.DB) CredentialRepository {
	return &credentialRepositoryImpl{db: db}
}

// credentialsByAccountAndTypeQuery is the base SELECT for querying credentials by account and type.
// Note: deleted_at is excluded because the WHERE clause guarantees only non-deleted rows are returned.
const credentialsByAccountAndTypeQuery = `
	SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
	       metadata, created_at, updated_at, verified_at, last_used_at
	FROM account_credentials
	WHERE account_id = $1 AND credential_type = $2 AND deleted_at IS NULL
	ORDER BY primary_credential DESC, created_at ASC`

// findByTypeAndIdentifierQuery is the base SELECT for querying a credential by type and identifier.
// Note: deleted_at is excluded because the WHERE clause guarantees only non-deleted rows are returned.
const findByTypeAndIdentifierQuery = `
	SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
	       metadata, created_at, updated_at, verified_at, last_used_at
	FROM account_credentials
	WHERE credential_type = $1 AND identifier = $2 AND deleted_at IS NULL
	LIMIT 1`

// CreateCredentials creates multiple credentials in a single batch INSERT.
func (r *credentialRepositoryImpl) CreateCredentials(ctx context.Context, tx *sql.Tx, credentials []*domain.Credential) error {
	if len(credentials) == 0 {
		return nil
	}

	const colsPerRow = 12
	var buf strings.Builder
	buf.WriteString(`INSERT INTO account_credentials
		(id, account_id, credential_type, identifier, credential_value, verified, primary_credential, metadata, created_at, updated_at, verified_at, last_used_at)
		VALUES `)

	args := make([]any, 0, len(credentials)*colsPerRow)
	for i, cred := range credentials {
		metadataJSON, err := json.Marshal(cred.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}

		if i > 0 {
			buf.WriteByte(',')
		}
		base := i * colsPerRow
		fmt.Fprintf(&buf, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+10, base+11, base+12)

		args = append(args,
			cred.ID,
			cred.AccountID,
			cred.Type,
			cred.Identifier,
			cred.Value,
			cred.Verified,
			cred.PrimaryCredential,
			metadataJSON,
			cred.CreatedAt,
			cred.UpdatedAt,
			cred.VerifiedAt,
			cred.LastUsedAt,
		)
	}

	_, err := tx.ExecContext(ctx, buf.String(), args...)
	if err != nil {
		return fmt.Errorf("batch insert credentials: %w", err)
	}

	return nil
}

// FindByAccountAndType finds credentials by account ID and type
func (r *credentialRepositoryImpl) FindByAccountAndType(ctx context.Context, accountID string, credType domain.CredentialType) ([]*domain.Credential, error) {
	return findByAccountAndType(ctx, r.db.QueryContext, accountID, credType)
}

// FindByAccountAndTypeTx finds credentials by account ID and type within a transaction.
func (r *credentialRepositoryImpl) FindByAccountAndTypeTx(ctx context.Context, tx *sql.Tx, accountID string, credType domain.CredentialType) ([]*domain.Credential, error) {
	return findByAccountAndType(ctx, tx.QueryContext, accountID, credType)
}

// findByAccountAndType is the shared implementation for both transactional and non-transactional variants.
func findByAccountAndType(ctx context.Context, queryFunc func(context.Context, string, ...any) (*sql.Rows, error), accountID string, credType domain.CredentialType) ([]*domain.Credential, error) {
	rows, err := queryFunc(ctx, credentialsByAccountAndTypeQuery, accountID, credType)
	if err != nil {
		return nil, fmt.Errorf("query credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	credentials, err := scanCredentials(rows)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// FindByAccountAndTypes finds credentials by account ID and multiple types in a single query.
func (r *credentialRepositoryImpl) FindByAccountAndTypes(ctx context.Context, accountID string, credTypes ...domain.CredentialType) ([]*domain.Credential, error) {
	if len(credTypes) == 0 {
		return nil, nil
	}

	var buf strings.Builder
	args := []any{accountID}
	buf.WriteString(`SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
	       metadata, created_at, updated_at, verified_at, last_used_at
	FROM account_credentials
	WHERE account_id = $1 AND deleted_at IS NULL AND credential_type IN (`)

	for i, ct := range credTypes {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, "$%d", i+2)
		args = append(args, ct)
	}
	buf.WriteString(")\n\tORDER BY primary_credential DESC, created_at ASC")

	rows, err := r.db.QueryContext(ctx, buf.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanCredentials(rows)
}

// FindByTypeAndIdentifier finds a credential by type and identifier
func (r *credentialRepositoryImpl) FindByTypeAndIdentifier(ctx context.Context, credType domain.CredentialType, identifier string) (*domain.Credential, error) {
	return findByTypeAndIdentifier(ctx, r.db.QueryRowContext, credType, identifier)
}

// FindByTypeAndIdentifierTx finds a credential by type and identifier within a transaction.
func (r *credentialRepositoryImpl) FindByTypeAndIdentifierTx(ctx context.Context, tx *sql.Tx, credType domain.CredentialType, identifier string) (*domain.Credential, error) {
	return findByTypeAndIdentifier(ctx, tx.QueryRowContext, credType, identifier)
}

// findByTypeAndIdentifier is the shared implementation for both transactional and non-transactional variants.
func findByTypeAndIdentifier(ctx context.Context, queryRow func(context.Context, string, ...any) *sql.Row, credType domain.CredentialType, identifier string) (*domain.Credential, error) {
	cred, err := scanCredential(queryRow(ctx, findByTypeAndIdentifierQuery, credType, identifier))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: type=%s", ErrCredentialNotFound, credType)
	}
	if err != nil {
		return nil, fmt.Errorf("query credential: %w", err)
	}

	return cred, nil
}

// FindPasswordCredential finds the primary password credential of an account.
func (r *credentialRepositoryImpl) FindPasswordCredential(ctx context.Context, accountID string) (*domain.Credential, error) {
	return findPasswordCredential(ctx, r.db.QueryRowContext, accountID)
}

// FindPasswordCredentialTx finds the primary password credential of an account within a transaction.
func (r *credentialRepositoryImpl) FindPasswordCredentialTx(ctx context.Context, tx *sql.Tx, accountID string) (*domain.Credential, error) {
	return findPasswordCredential(ctx, tx.QueryRowContext, accountID)
}

// findPasswordCredential is the shared implementation for both transactional and non-transactional variants.
func findPasswordCredential(ctx context.Context, queryRow func(context.Context, string, ...any) *sql.Row, accountID string) (*domain.Credential, error) {
	query := `
		SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
		       metadata, created_at, updated_at, verified_at, last_used_at
		FROM account_credentials
		WHERE account_id = $1 AND credential_type = $2 AND deleted_at IS NULL
		ORDER BY primary_credential DESC, created_at ASC
		LIMIT 1`

	cred, err := scanCredential(queryRow(ctx, query, accountID, domain.CredentialTypePassword))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: account=%s", ErrCredentialNotFound, accountID)
	}
	if err != nil {
		return nil, fmt.Errorf("find password credential: %w", err)
	}

	return cred, nil
}

// UpdateCredential updates a credential
func (r *credentialRepositoryImpl) UpdateCredential(ctx context.Context, tx *sql.Tx, credential *domain.Credential) error {
	query := `
		UPDATE account_credentials
		SET identifier = $1, credential_value = $2, verified = $3, primary_credential = $4,
		    metadata = $5, verified_at = $6, last_used_at = $7, updated_at = $8
		WHERE id = $9 AND deleted_at IS NULL
	`

	metadataJSON, err := json.Marshal(credential.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	now := time.Now()
	result, err := tx.ExecContext(ctx, query,
		credential.Identifier,
		credential.Value,
		credential.Verified,
		credential.PrimaryCredential,
		metadataJSON,
		credential.VerifiedAt,
		credential.LastUsedAt,
		now,
		credential.ID,
	)
	if err != nil {
		return fmt.Errorf("update credential: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrCredentialNotFound, credential.ID)
	}

	return nil
}

// UpdateLastUsedAt updates only the last_used_at timestamp of a credential.
// This avoids overwriting concurrent changes to other credential fields.
func (r *credentialRepositoryImpl) UpdateLastUsedAt(ctx context.Context, tx *sql.Tx, credentialID string, lastUsedAt time.Time) error {
	query := `
		UPDATE account_credentials
		SET last_used_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, lastUsedAt, credentialID)
	if err != nil {
		return fmt.Errorf("update last_used_at: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrCredentialNotFound, credentialID)
	}

	return nil
}

// SoftDeleteCredentialsByAccount soft deletes all credentials of an account.
// Returns nil even if zero rows are affected (idempotent for bulk delete).
func (r *credentialRepositoryImpl) SoftDeleteCredentialsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `
		UPDATE account_credentials
		SET deleted_at = $1, updated_at = $1, credential_value = NULL, identifier = NULL
		WHERE account_id = $2 AND deleted_at IS NULL
	`

	_, err := tx.ExecContext(ctx, query, deletedAt, accountID)
	if err != nil {
		return fmt.Errorf("soft delete credentials: %w", err)
	}

	return nil
}

// SoftDeleteCredentialsByType soft deletes all credentials of a given type for an account.
// Returns nil even if zero rows are affected (idempotent for bulk delete).
func (r *credentialRepositoryImpl) SoftDeleteCredentialsByType(ctx context.Context, tx *sql.Tx, accountID string, credType domain.CredentialType, deletedAt time.Time) error {
	query := `
		UPDATE account_credentials
		SET deleted_at = $1, updated_at = $1, credential_value = NULL, identifier = NULL
		WHERE account_id = $2 AND credential_type = $3 AND deleted_at IS NULL
	`

	_, err := tx.ExecContext(ctx, query, deletedAt, accountID, credType)
	if err != nil {
		return fmt.Errorf("soft delete %s credentials: %w", credType, err)
	}

	return nil
}

// SoftDeleteCredential soft deletes a single credential
func (r *credentialRepositoryImpl) SoftDeleteCredential(ctx context.Context, tx *sql.Tx, credentialID string, deletedAt time.Time) error {
	query := `
		UPDATE account_credentials
		SET deleted_at = $1, updated_at = $1, credential_value = NULL, identifier = NULL
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, credentialID)
	if err != nil {
		return fmt.Errorf("soft delete credential: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrCredentialNotFound, credentialID)
	}

	return nil
}

// FindByAccountAndTypeForUpdate finds credentials by account ID and type with row-level locking.
func (r *credentialRepositoryImpl) FindByAccountAndTypeForUpdate(ctx context.Context, tx *sql.Tx, accountID string, credType domain.CredentialType) ([]*domain.Credential, error) {
	query := credentialsByAccountAndTypeQuery + "\n\tFOR UPDATE"

	rows, err := tx.QueryContext(ctx, query, accountID, credType)
	if err != nil {
		return nil, fmt.Errorf("query credentials for update: %w", err)
	}
	defer func() { _ = rows.Close() }()

	credentials, err := scanCredentials(rows)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// VerifyFirstUnverifiedTOTP atomically verifies the first unverified TOTP credential for an account.
func (r *credentialRepositoryImpl) VerifyFirstUnverifiedTOTP(ctx context.Context, tx *sql.Tx, accountID string) (bool, error) {
	// First check if there's an unverified TOTP credential to avoid masking
	// subquery errors behind a silent rowsAffected=0.
	checkQuery := `
		SELECT id FROM account_credentials
		WHERE account_id = $1 AND credential_type = $2 AND verified = false AND deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`
	var credID string
	if err := tx.QueryRowContext(ctx, checkQuery, accountID, string(domain.CredentialTypeTOTP)).Scan(&credID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("find unverified TOTP credential: %w", err)
	}

	updateQuery := `
		UPDATE account_credentials
		SET verified = true, verified_at = NOW()
		WHERE id = $1
	`
	result, err := tx.ExecContext(ctx, updateQuery, credID)
	if err != nil {
		return false, fmt.Errorf("verify first unverified TOTP: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}
