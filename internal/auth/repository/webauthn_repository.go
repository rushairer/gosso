package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// WebAuthnCredentialRepository defines the webauthn credential repository interface
type WebAuthnCredentialRepository interface {
	CreateCredential(ctx context.Context, tx *sql.Tx, cred *domain.WebAuthnCredential) error
	FindByCredentialID(ctx context.Context, credentialID string) (*domain.WebAuthnCredential, error)
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.WebAuthnCredential, error)
	UpdateCredential(ctx context.Context, tx *sql.Tx, cred *domain.WebAuthnCredential) error
	SoftDeleteCredential(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error
	SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
}

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
	`

	cred := &domain.WebAuthnCredential{}
	var transportsJSON []byte
	var lastUsedAt, deletedAt *time.Time

	err := r.db.QueryRowContext(ctx, query, credentialID).Scan(
		&cred.ID,
		&cred.AccountID,
		&cred.CredentialID,
		&cred.PublicKey,
		&cred.SignCount,
		&cred.AAGUID,
		&transportsJSON,
		&cred.AttestationType,
		&cred.Name,
		&cred.Verified,
		&cred.CreatedAt,
		&lastUsedAt,
		&deletedAt,
	)
	if err != nil {
		return nil, err
	}

	cred.LastUsedAt = lastUsedAt
	cred.DeletedAt = deletedAt

	if transportsJSON != nil {
		if err := json.Unmarshal(transportsJSON, &cred.Transports); err != nil {
			return nil, fmt.Errorf("unmarshal transports: %w", err)
		}
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
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var credentials []*domain.WebAuthnCredential
	for rows.Next() {
		cred := &domain.WebAuthnCredential{}
		var transportsJSON []byte
		var lastUsedAt, deletedAt *time.Time

		if err := rows.Scan(
			&cred.ID,
			&cred.AccountID,
			&cred.CredentialID,
			&cred.PublicKey,
			&cred.SignCount,
			&cred.AAGUID,
			&transportsJSON,
			&cred.AttestationType,
			&cred.Name,
			&cred.Verified,
			&cred.CreatedAt,
			&lastUsedAt,
			&deletedAt,
		); err != nil {
			return nil, err
		}

		cred.LastUsedAt = lastUsedAt
		cred.DeletedAt = deletedAt

		if transportsJSON != nil {
			if err := json.Unmarshal(transportsJSON, &cred.Transports); err != nil {
				return nil, fmt.Errorf("unmarshal transports: %w", err)
			}
		}

		credentials = append(credentials, cred)
	}

	return credentials, rows.Err()
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

	_, err = tx.ExecContext(ctx, query,
		cred.ID,
		cred.SignCount,
		transportsJSON,
		cred.LastUsedAt,
		cred.Name,
	)
	if err != nil {
		return fmt.Errorf("update webauthn credential: %w", err)
	}

	return nil
}

func (r *webAuthnCredentialRepositoryImpl) SoftDeleteCredential(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error {
	query := `UPDATE webauthn_credentials SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL`
	_, err := tx.ExecContext(ctx, query, id, deletedAt)
	return err
}

func (r *webAuthnCredentialRepositoryImpl) SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `UPDATE webauthn_credentials SET deleted_at = $2 WHERE account_id = $1 AND deleted_at IS NULL`
	_, err := tx.ExecContext(ctx, query, accountID, deletedAt)
	return err
}
