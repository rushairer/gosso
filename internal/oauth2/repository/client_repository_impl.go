package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

type oauth2ClientRepositoryImpl struct {
	db *sql.DB
}

// NewOAuth2ClientRepository creates a new OAuth2 client repository instance
func NewOAuth2ClientRepository(db *sql.DB) OAuth2ClientRepository {
	return &oauth2ClientRepositoryImpl{db: db}
}

// clientJSONFields holds raw JSON bytes for the five JSON columns of an oauth2_clients row.
type clientJSONFields struct {
	redirectURIs   []byte
	postLogoutURIs []byte
	grantTypes     []byte
	scopes         []byte
	metadata       []byte
}

// unmarshalClientJSONFields populates an OAuth2Client's JSON columns from raw bytes.
func unmarshalClientJSONFields(client *domain.OAuth2Client, f *clientJSONFields) error {
	if err := json.Unmarshal(f.redirectURIs, &client.RedirectURIs); err != nil {
		return fmt.Errorf("unmarshal redirect_uris: %w", err)
	}
	if err := json.Unmarshal(f.postLogoutURIs, &client.PostLogoutRedirectURIs); err != nil {
		return fmt.Errorf("unmarshal post_logout_redirect_uris: %w", err)
	}
	if err := json.Unmarshal(f.grantTypes, &client.GrantTypes); err != nil {
		return fmt.Errorf("unmarshal grant_types: %w", err)
	}
	if err := json.Unmarshal(f.scopes, &client.Scopes); err != nil {
		return fmt.Errorf("unmarshal scopes: %w", err)
	}
	if f.metadata != nil {
		if err := json.Unmarshal(f.metadata, &client.Metadata); err != nil {
			return fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return nil
}

// marshalClientJSONFields serializes an OAuth2Client's JSON columns to raw bytes.
func marshalClientJSONFields(client *domain.OAuth2Client) (*clientJSONFields, error) {
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("marshal redirect_uris: %w", err)
	}
	postLogoutURIs, err := json.Marshal(client.PostLogoutRedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("marshal post_logout_redirect_uris: %w", err)
	}
	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return nil, fmt.Errorf("marshal grant_types: %w", err)
	}
	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return nil, fmt.Errorf("marshal scopes: %w", err)
	}
	var metadata []byte
	if client.Metadata != nil {
		metadata, err = json.Marshal(client.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshal metadata: %w", err)
		}
	}
	return &clientJSONFields{
		redirectURIs:   redirectURIs,
		postLogoutURIs: postLogoutURIs,
		grantTypes:     grantTypes,
		scopes:         scopes,
		metadata:       metadata,
	}, nil
}

func (r *oauth2ClientRepositoryImpl) Create(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client) error {
	f, err := marshalClientJSONFields(client)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO oauth2_clients (account_id, client_id, client_secret_hash, name, description, redirect_uris, post_logout_redirect_uris, grant_types, scopes, is_confidential, metadata, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id, created_at, updated_at`

	err = tx.QueryRowContext(ctx, query,
		client.AccountID,
		client.ClientID,
		client.ClientSecretHash,
		client.Name,
		client.Description,
		f.redirectURIs,
		f.postLogoutURIs,
		f.grantTypes,
		f.scopes,
		client.IsConfidential,
		f.metadata,
		client.FrontchannelLogoutURI,
		client.FrontchannelLogoutSessionRequired,
		client.BackchannelLogoutURI,
		client.BackchannelLogoutSessionRequired,
	).Scan(&client.ID, &client.CreatedAt, &client.UpdatedAt)

	if err != nil {
		return fmt.Errorf("insert oauth2_client: %w", err)
	}

	return nil
}

func (r *oauth2ClientRepositoryImpl) FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	return findByClientID(ctx, r.db.QueryRowContext, clientID)
}

func (r *oauth2ClientRepositoryImpl) FindByClientIDTx(ctx context.Context, tx *sql.Tx, clientID string) (*domain.OAuth2Client, error) {
	return findByClientID(ctx, tx.QueryRowContext, clientID)
}

// findByClientID is the shared implementation for both transactional and non-transactional variants.
func findByClientID(ctx context.Context, queryRow func(context.Context, string, ...any) *sql.Row, clientID string) (*domain.OAuth2Client, error) {
	const query = `
		SELECT id, account_id, client_id, client_secret_hash, name, description, redirect_uris, post_logout_redirect_uris, grant_types, scopes, is_confidential, metadata, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at, deleted_at
		FROM oauth2_clients
		WHERE client_id = $1 AND deleted_at IS NULL`

	client, err := scanOAuth2Client(queryRow(ctx, query, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", domain.ErrClientNotFound, clientID)
	}
	if err != nil {
		return nil, fmt.Errorf("find oauth2_client by client_id: %w", err)
	}

	return client, nil
}

func (r *oauth2ClientRepositoryImpl) FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error) {
	query := `
		SELECT id, account_id, client_id, client_secret_hash, name, description, redirect_uris, post_logout_redirect_uris, grant_types, scopes, is_confidential, metadata, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at, deleted_at
		FROM oauth2_clients
		WHERE account_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("find oauth2_clients by account_id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanOAuth2Clients(rows)
}

func (r *oauth2ClientRepositoryImpl) Update(ctx context.Context, tx *sql.Tx, client *domain.OAuth2Client, expectedUpdatedAt time.Time) error {
	f, err := marshalClientJSONFields(client)
	if err != nil {
		return err
	}

	query := `
		UPDATE oauth2_clients
		SET name = $1, description = $2, redirect_uris = $3, post_logout_redirect_uris = $4, grant_types = $5, scopes = $6, metadata = $7, frontchannel_logout_uri = $8, frontchannel_logout_session_required = $9, backchannel_logout_uri = $10, backchannel_logout_session_required = $11, updated_at = $12
		WHERE id = $13 AND deleted_at IS NULL AND updated_at = $14
		RETURNING updated_at`

	err = tx.QueryRowContext(ctx, query,
		client.Name, client.Description, f.redirectURIs, f.postLogoutURIs, f.grantTypes, f.scopes, f.metadata,
		client.FrontchannelLogoutURI, client.FrontchannelLogoutSessionRequired,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired,
		time.Now(), client.ID, expectedUpdatedAt,
	).Scan(&client.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		// Distinguish not-found from concurrent modification
		_, findErr := findByClientID(ctx, tx.QueryRowContext, client.ClientID)
		if findErr != nil {
			return findErr // ErrClientNotFound
		}
		return fmt.Errorf("%w: %s", domain.ErrClientConcurrentModification, client.ID)
	}
	if err != nil {
		return fmt.Errorf("update oauth2_client: %w", err)
	}

	return nil
}

func (r *oauth2ClientRepositoryImpl) SoftDelete(ctx context.Context, tx *sql.Tx, id string, deletedAt time.Time) error {
	query := `UPDATE oauth2_clients SET deleted_at = $1, updated_at = $1, client_secret_hash = '' WHERE id = $2 AND deleted_at IS NULL`
	result, err := tx.ExecContext(ctx, query, deletedAt, id)
	if err != nil {
		return fmt.Errorf("soft delete oauth2_client: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", domain.ErrClientNotFound, id)
	}
	return nil
}

// SoftDeleteByAccountID soft deletes all OAuth2 clients of an account.
// Returns nil even if zero rows are affected (idempotent for bulk delete).
func (r *oauth2ClientRepositoryImpl) SoftDeleteByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `UPDATE oauth2_clients SET deleted_at = $1, updated_at = $1, client_secret_hash = '' WHERE account_id = $2 AND deleted_at IS NULL`
	_, err := tx.ExecContext(ctx, query, deletedAt, accountID)
	if err != nil {
		return fmt.Errorf("soft delete oauth2_clients by account_id: %w", err)
	}
	return nil
}

// FindFrontchannelLogoutClientsByAccountID returns clients that have a
// non-empty frontchannel_logout_uri and a non-deleted consent for the account.
func (r *oauth2ClientRepositoryImpl) FindFrontchannelLogoutClientsByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error) {
	query := `
		SELECT c.id, c.account_id, c.client_id, c.client_secret_hash, c.name, c.description,
		       c.redirect_uris, c.post_logout_redirect_uris, c.grant_types, c.scopes,
		       c.is_confidential, c.metadata,
		       c.frontchannel_logout_uri, c.frontchannel_logout_session_required,
		       c.backchannel_logout_uri, c.backchannel_logout_session_required,
		       c.created_at, c.updated_at, c.deleted_at
		FROM oauth2_clients c
		INNER JOIN oauth2_consents oc ON oc.client_id = c.id AND oc.account_id = $1 AND oc.deleted_at IS NULL
		WHERE c.frontchannel_logout_uri != '' AND c.deleted_at IS NULL`

	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("find frontchannel logout clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanOAuth2Clients(rows)
}

// FindBackchannelLogoutClientsByAccountID returns clients that have a
// non-empty backchannel_logout_uri and a non-deleted consent for the account.
func (r *oauth2ClientRepositoryImpl) FindBackchannelLogoutClientsByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error) {
	query := `
		SELECT c.id, c.account_id, c.client_id, c.client_secret_hash, c.name, c.description,
		       c.redirect_uris, c.post_logout_redirect_uris, c.grant_types, c.scopes,
		       c.is_confidential, c.metadata,
		       c.frontchannel_logout_uri, c.frontchannel_logout_session_required,
		       c.backchannel_logout_uri, c.backchannel_logout_session_required,
		       c.created_at, c.updated_at, c.deleted_at
		FROM oauth2_clients c
		INNER JOIN oauth2_consents oc ON oc.client_id = c.id AND oc.account_id = $1 AND oc.deleted_at IS NULL
		WHERE c.backchannel_logout_uri != '' AND c.deleted_at IS NULL`

	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("find backchannel logout clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanOAuth2Clients(rows)
}
