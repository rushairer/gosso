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

type credentialRepositoryImpl struct {
	db *sql.DB
}

// NewCredentialRepository creates a new credential repository
func NewCredentialRepository(db *sql.DB) CredentialRepository {
	return &credentialRepositoryImpl{db: db}
}

// credentialsByAccountAndTypeQuery is the base SELECT for querying credentials by account and type.
const credentialsByAccountAndTypeQuery = `
	SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
	       metadata, created_at, verified_at, last_used_at, deleted_at
	FROM account_credentials
	WHERE account_id = $1 AND credential_type = $2 AND deleted_at IS NULL
	ORDER BY primary_credential DESC, created_at ASC`

// CreateCredentials creates multiple credentials
func (r *credentialRepositoryImpl) CreateCredentials(ctx context.Context, tx *sql.Tx, credentials []*domain.Credential) error {
	query := `
		INSERT INTO account_credentials
		(id, account_id, credential_type, identifier, credential_value, verified, primary_credential, metadata, created_at, verified_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	for _, cred := range credentials {
		metadataJSON, err := json.Marshal(cred.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}

		_, err = tx.ExecContext(ctx, query,
			cred.ID,
			cred.AccountID,
			cred.Type,
			cred.Identifier,
			cred.Value,
			cred.Verified,
			cred.PrimaryCredential,
			metadataJSON,
			cred.CreatedAt,
			cred.VerifiedAt,
			cred.LastUsedAt,
		)
		if err != nil {
			return fmt.Errorf("insert credential %s: %w", cred.Type, err)
		}
	}

	return nil
}

// FindByAccountAndType finds credentials by account ID and type
func (r *credentialRepositoryImpl) FindByAccountAndType(ctx context.Context, accountID string, credType domain.CredentialType) ([]*domain.Credential, error) {
	rows, err := r.db.QueryContext(ctx, credentialsByAccountAndTypeQuery, accountID, credType)
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

// FindByAccountAndTypeTx finds credentials by account ID and type within a transaction.
func (r *credentialRepositoryImpl) FindByAccountAndTypeTx(ctx context.Context, tx *sql.Tx, accountID string, credType domain.CredentialType) ([]*domain.Credential, error) {
	rows, err := tx.QueryContext(ctx, credentialsByAccountAndTypeQuery, accountID, credType)
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

// FindByTypeAndIdentifier finds a credential by type and identifier
func (r *credentialRepositoryImpl) FindByTypeAndIdentifier(ctx context.Context, credType domain.CredentialType, identifier string) (*domain.Credential, error) {
	query := `
		SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
		       metadata, created_at, verified_at, last_used_at, deleted_at
		FROM account_credentials
		WHERE credential_type = $1 AND identifier = $2 AND deleted_at IS NULL
		LIMIT 1
	`

	cred, err := scanCredential(r.db.QueryRowContext(ctx, query, credType, identifier))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: type=%s identifier=%s", ErrCredentialNotFound, credType, identifier)
	}
	if err != nil {
		return nil, fmt.Errorf("query credential: %w", err)
	}

	return cred, nil
}

// FindByTypeAndIdentifierTx finds a credential by type and identifier within a transaction.
func (r *credentialRepositoryImpl) FindByTypeAndIdentifierTx(ctx context.Context, tx *sql.Tx, credType domain.CredentialType, identifier string) (*domain.Credential, error) {
	query := `
		SELECT id, account_id, credential_type, identifier, credential_value, verified, primary_credential,
		       metadata, created_at, verified_at, last_used_at, deleted_at
		FROM account_credentials
		WHERE credential_type = $1 AND identifier = $2 AND deleted_at IS NULL
		LIMIT 1
	`

	cred, err := scanCredential(tx.QueryRowContext(ctx, query, credType, identifier))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: type=%s identifier=%s", ErrCredentialNotFound, credType, identifier)
	}
	if err != nil {
		return nil, fmt.Errorf("query credential: %w", err)
	}

	return cred, nil
}

// FindPasswordCredential finds password credential of an account
func (r *credentialRepositoryImpl) FindPasswordCredential(ctx context.Context, accountID string) (*domain.Credential, error) {
	credentials, err := r.FindByAccountAndType(ctx, accountID, domain.CredentialTypePassword)
	if err != nil {
		return nil, err
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("%w: account=%s", ErrCredentialNotFound, accountID)
	}

	return credentials[0], nil
}

// UpdateCredential updates a credential
func (r *credentialRepositoryImpl) UpdateCredential(ctx context.Context, tx *sql.Tx, credential *domain.Credential) error {
	query := `
		UPDATE account_credentials
		SET identifier = $1, credential_value = $2, verified = $3, primary_credential = $4,
		    metadata = $5, verified_at = $6, last_used_at = $7
		WHERE id = $8 AND deleted_at IS NULL
	`

	metadataJSON, err := json.Marshal(credential.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	result, err := tx.ExecContext(ctx, query,
		credential.Identifier,
		credential.Value,
		credential.Verified,
		credential.PrimaryCredential,
		metadataJSON,
		credential.VerifiedAt,
		credential.LastUsedAt,
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

// SoftDeleteCredentialsByAccount soft deletes all credentials of an account
func (r *credentialRepositoryImpl) SoftDeleteCredentialsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `
		UPDATE account_credentials
		SET deleted_at = $1, updated_at = $1
		WHERE account_id = $2 AND deleted_at IS NULL
	`

	_, err := tx.ExecContext(ctx, query, deletedAt, accountID)
	if err != nil {
		return fmt.Errorf("soft delete credentials: %w", err)
	}

	return nil
}

// SoftDeleteCredential soft deletes a single credential
func (r *credentialRepositoryImpl) SoftDeleteCredential(ctx context.Context, tx *sql.Tx, credentialID string, deletedAt time.Time) error {
	query := `
		UPDATE account_credentials
		SET deleted_at = $1, updated_at = $1
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
	query := `
		UPDATE account_credentials
		SET verified = true, verified_at = NOW()
		WHERE id = (
			SELECT id FROM account_credentials
			WHERE account_id = $1 AND credential_type = 'totp' AND verified = false AND deleted_at IS NULL
			ORDER BY created_at DESC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
	`

	result, err := tx.ExecContext(ctx, query, accountID)
	if err != nil {
		return false, fmt.Errorf("verify first unverified TOTP: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}
