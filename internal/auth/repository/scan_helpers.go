package repository

import (
	"encoding/base64"
	"fmt"
	"time"

	dbPkg "github.com/rushairer/gosso/internal/db"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// scanWebAuthnCredential scans all 15 columns of a webauthn_credentials row
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
		&cred.Flags,
		&cred.Verified,
		&cred.CreatedAt,
		&cred.UpdatedAt,
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

	// credential_id is stored as base64-encoded text in the database.
	// Decode back to the raw authenticator bytes that the webauthn library expects.
	if len(cred.CredentialID) > 0 {
		decoded, err := base64.RawURLEncoding.DecodeString(string(cred.CredentialID))
		if err != nil {
			return nil, fmt.Errorf("decode credential_id: %w", err)
		}
		cred.CredentialID = decoded
	}

	return cred, nil
}
