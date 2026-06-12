package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/auth/domain"
)

type webAuthnCredentialRepositoryImpl struct {
	db *sql.DB
}

// NewWebAuthnCredentialRepository creates a new WebAuthn credential repository
func NewWebAuthnCredentialRepository(db *sql.DB) WebAuthnCredentialRepository {
	return &webAuthnCredentialRepositoryImpl{db: db}
}

func (r *webAuthnCredentialRepositoryImpl) CreateCredential(ctx context.Context, tx *sql.Tx, cred *domain.WebAuthnCredential) error {
	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("marshal transports: %w", err)
	}

	query := `
		INSERT INTO webauthn_credentials
		(id, account_id, credential_id, public_key, sign_count, aaguid, transports, attestation_type, name, verified, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = tx.ExecContext(ctx, query,
		cred.ID,
		cred.AccountID,
		cred.CredentialID,
		cred.PublicKey,
		cred.SignCount,
		cred.AAGUID,
		transportsJSON,
		cred.AttestationType,
		cred.Name,
		cred.Verified,
		cred.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert webauthn credential: %w", err)
	}

	return nil
}

func (r *webAuthnCredentialRepositoryImpl) FindByCredentialID(ctx context.Context, credentialID string) (*domain.WebAuthnCredential, error) {
	query := `
		SELECT id, account_id, credential_id, public_key, sign_count, aaguid, transports, attestation_type, name, verified, created_at, last_used_at, deleted_at
		FROM webauthn_credentials
		WHERE credential_id = $1 AND deleted_at IS NULL
		LIMIT 1
	`

	cred, err := scanWebAuthnCredential(r.db.QueryRowContext(ctx, query, credentialID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrWebAuthnCredentialNotFound, credentialID)
		}
		return nil, fmt.Errorf("find webauthn credential: %w", err)
	}

	return cred, nil
}

func (r *webAuthnCredentialRepositoryImpl) FindByAccountID(ctx context.Context, accountID string) ([]*domain.WebAuthnCredential, error) {
	query := `
		SELECT id, account_id, credential_id, public_key, sign_count, aaguid, transports, attestation_type, name, verified, created_at, last_used_at, deleted_at
		FROM webauthn_credentials
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("find webauthn credentials by account_id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var credentials []*domain.WebAuthnCredential
	for rows.Next() {
		cred, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		credentials = append(credentials, cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webauthn credentials: %w", err)
	}
	return credentials, nil
}

func (r *webAuthnCredentialRepositoryImpl) UpdateCredential(ctx context.Context, tx *sql.Tx, cred *domain.WebAuthnCredential) error {
	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("marshal transports: %w", err)
	}

	query := `
		UPDATE webauthn_credentials
		SET sign_count = $2, transports = $3, last_used_at = $4, name = $5
		WHERE id = $1 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query,
		cred.ID,
		cred.SignCount,
		transportsJSON,
		cred.LastUsedAt,
		cred.Name,
	)
	if err != nil {
		return fmt.Errorf("update webauthn credential: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrWebAuthnCredentialNotFound, cred.ID)
	}

	return nil
}

func (r *webAuthnCredentialRepositoryImpl) SoftDeleteCredential(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error {
	query := `UPDATE webauthn_credentials SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`
	result, err := tx.ExecContext(ctx, query, id, deletedAt)
	if err != nil {
		return fmt.Errorf("soft delete webauthn credential: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrWebAuthnCredentialNotFound, id)
	}
	return nil
}

func (r *webAuthnCredentialRepositoryImpl) SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `UPDATE webauthn_credentials SET deleted_at = $2, updated_at = $2 WHERE account_id = $1 AND deleted_at IS NULL`
	_, err := tx.ExecContext(ctx, query, accountID, deletedAt)
	if err != nil {
		return fmt.Errorf("soft delete webauthn credentials by account_id: %w", err)
	}
	return nil
}
