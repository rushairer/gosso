package repository

import (
	"database/sql"
	"fmt"

	dbPkg "github.com/rushairer/gosso/internal/db"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

// scanOAuth2Client scans a single oauth2_clients row (14 columns) into an OAuth2Client.
func scanOAuth2Client(s dbPkg.Scannable) (*domain.OAuth2Client, error) {
	client := &domain.OAuth2Client{}
	var redirectURIs, postLogoutURIs, grantTypes, scopes, metadata []byte

	if err := s.Scan(
		&client.ID, &client.AccountID, &client.ClientID, &client.ClientSecretHash,
		&client.Name, &client.Description, &redirectURIs, &postLogoutURIs, &grantTypes, &scopes,
		&client.IsConfidential, &metadata, &client.CreatedAt, &client.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if err := unmarshalClientJSONFields(client, &clientJSONFields{
		redirectURIs: redirectURIs, postLogoutURIs: postLogoutURIs,
		grantTypes: grantTypes, scopes: scopes, metadata: metadata,
	}); err != nil {
		return nil, err
	}

	return client, nil
}

// scanOAuth2Clients iterates all rows and returns a slice of OAuth2Client.
func scanOAuth2Clients(rows *sql.Rows) ([]*domain.OAuth2Client, error) {
	var clients []*domain.OAuth2Client
	for rows.Next() {
		client, err := scanOAuth2Client(rows)
		if err != nil {
			return nil, fmt.Errorf("scan oauth2_client: %w", err)
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate clients: %w", err)
	}
	return clients, nil
}

// scanConsent scans a single oauth2_consents row (7 columns) into a Consent.
func scanConsent(s dbPkg.Scannable) (*domain.Consent, error) {
	var consent domain.Consent
	var scopesJSON []byte

	if err := s.Scan(
		&consent.ID,
		&consent.AccountID,
		&consent.ClientID,
		&scopesJSON,
		&consent.GrantedAt,
		&consent.CreatedAt,
		&consent.UpdatedAt,
	); err != nil {
		return nil, err
	}

	consent.Scopes = make([]string, 0)
	if err := dbPkg.UnmarshalJSONField(scopesJSON, &consent.Scopes, "scopes"); err != nil {
		return nil, err
	}

	return &consent, nil
}

// scanConsents iterates all rows and returns a slice of Consent.
func scanConsents(rows *sql.Rows) ([]*domain.Consent, error) {
	var consents []*domain.Consent
	for rows.Next() {
		consent, err := scanConsent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan consent: %w", err)
		}
		consents = append(consents, consent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate consents: %w", err)
	}
	return consents, nil
}
