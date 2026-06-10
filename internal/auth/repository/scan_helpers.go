package repository

import (
	"encoding/json"
	"time"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// scannable is satisfied by both *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...any) error
}

// scanWebAuthnCredential scans all 13 columns of a webauthn_credentials row
// into a new WebAuthnCredential. Returns the raw scan error so callers can
// check for sql.ErrNoRows.
func scanWebAuthnCredential(s scannable) (*domain.WebAuthnCredential, error) {
	cred := &domain.WebAuthnCredential{}
	var transportsJSON []byte
	var lastUsedAt, deletedAt *time.Time

	err := s.Scan(
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
			return nil, err
		}
	}

	return cred, nil
}
