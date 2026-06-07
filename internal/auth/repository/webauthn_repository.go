package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// Sentinel errors for repository operations
var (
	ErrWebAuthnCredentialNotFound = errors.New("webauthn credential not found")
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
