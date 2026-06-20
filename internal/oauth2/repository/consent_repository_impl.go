package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/oauth2/domain"
)

type consentRepositoryImpl struct {
	db *sql.DB
}

// NewConsentRepository creates a new consent repository instance.
func NewConsentRepository(db *sql.DB) ConsentRepository {
	return &consentRepositoryImpl{db: db}
}

// Upsert inserts or updates a consent record.
func (r *consentRepositoryImpl) Upsert(ctx context.Context, tx *sql.Tx, consent *domain.Consent) error {
	scopesJSON, err := json.Marshal(consent.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}

	query := `
		INSERT INTO oauth2_consents (account_id, client_id, scopes, granted_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (account_id, client_id)
		DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = EXCLUDED.granted_at, deleted_at = NULL
		RETURNING id, created_at, updated_at`

	if err := tx.QueryRowContext(ctx, query,
		consent.AccountID,
		consent.ClientID,
		scopesJSON,
		consent.GrantedAt,
	).Scan(&consent.ID, &consent.CreatedAt, &consent.UpdatedAt); err != nil {
		return fmt.Errorf("upsert consent: %w", err)
	}
	return nil
}

// FindByAccountAndClient finds a consent record by account and client ID.
// Only returns non-deleted records.
func (r *consentRepositoryImpl) FindByAccountAndClient(ctx context.Context, accountID, clientID string) (*domain.Consent, error) {
	return findConsentByAccountAndClient(ctx, r.db, accountID, clientID)
}

// FindByAccountAndClientTx finds a consent record within a transaction.
func (r *consentRepositoryImpl) FindByAccountAndClientTx(ctx context.Context, tx *sql.Tx, accountID, clientID string) (*domain.Consent, error) {
	return findConsentByAccountAndClient(ctx, tx, accountID, clientID)
}

// findConsentByAccountAndClient is the shared implementation for FindByAccountAndClient and FindByAccountAndClientTx.
func findConsentByAccountAndClient(ctx context.Context, q db.Queryable, accountID, clientID string) (*domain.Consent, error) {
	query := `
		SELECT id, account_id, client_id, scopes, granted_at, created_at, updated_at, deleted_at
		FROM oauth2_consents
		WHERE account_id = $1 AND client_id = $2 AND deleted_at IS NULL`

	consent, err := scanConsent(q.QueryRowContext(ctx, query, accountID, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: account=%s client=%s", domain.ErrConsentNotFound, accountID, clientID)
	}
	if err != nil {
		return nil, fmt.Errorf("find consent: %w", err)
	}

	return consent, nil
}

// SoftDelete soft-deletes a consent record.
func (r *consentRepositoryImpl) SoftDelete(ctx context.Context, tx *sql.Tx, accountID, clientID string, deletedAt time.Time) error {
	query := `UPDATE oauth2_consents SET deleted_at = $3, updated_at = $3 WHERE account_id = $1 AND client_id = $2 AND deleted_at IS NULL`
	result, err := tx.ExecContext(ctx, query, accountID, clientID, deletedAt)
	if err != nil {
		return fmt.Errorf("soft delete consent: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: account=%s client=%s", domain.ErrConsentNotFound, accountID, clientID)
	}
	return nil
}
