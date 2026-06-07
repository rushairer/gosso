package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

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
		DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = EXCLUDED.granted_at
		RETURNING id, created_at, updated_at`

	return tx.QueryRowContext(ctx, query,
		consent.AccountID,
		consent.ClientID,
		scopesJSON,
		consent.GrantedAt,
	).Scan(&consent.ID, &consent.CreatedAt, &consent.UpdatedAt)
}

// FindByAccountAndClient finds a consent record by account and client ID.
func (r *consentRepositoryImpl) FindByAccountAndClient(ctx context.Context, accountID, clientID string) (*domain.Consent, error) {
	query := `
		SELECT id, account_id, client_id, scopes, granted_at, created_at, updated_at
		FROM oauth2_consents
		WHERE account_id = $1 AND client_id = $2`

	var consent domain.Consent
	var scopesJSON []byte
	err := r.db.QueryRowContext(ctx, query, accountID, clientID).Scan(
		&consent.ID,
		&consent.AccountID,
		&consent.ClientID,
		&scopesJSON,
		&consent.GrantedAt,
		&consent.CreatedAt,
		&consent.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find consent: %w", err)
	}

	if err := json.Unmarshal(scopesJSON, &consent.Scopes); err != nil {
		return nil, fmt.Errorf("unmarshal scopes: %w", err)
	}

	return &consent, nil
}

// Delete removes a consent record.
func (r *consentRepositoryImpl) Delete(ctx context.Context, tx *sql.Tx, accountID, clientID string) error {
	query := `DELETE FROM oauth2_consents WHERE account_id = $1 AND client_id = $2`
	_, err := tx.ExecContext(ctx, query, accountID, clientID)
	if err != nil {
		return fmt.Errorf("delete consent: %w", err)
	}
	return nil
}
