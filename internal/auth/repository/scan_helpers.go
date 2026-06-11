package repository

import (
	"time"

	dbPkg "github.com/rushairer/gosso/internal/db"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// scanWebAuthnCredential scans all 13 columns of a webauthn_credentials row
// into a new WebAuthnCredential. Returns the raw scan error so callers can
// check for sql.ErrNoRows.
func scanWebAuthnCredential(s dbPkg.Scannable) (*domain.WebAuthnCredential, error) {
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

	if err := dbPkg.UnmarshalJSONField(transportsJSON, &cred.Transports, "transports"); err != nil {
		return nil, err
	}

	return cred, nil
}
