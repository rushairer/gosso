package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

// Sentinel errors for repository operations
var (
	ErrCredentialNotFound = errors.New("credential not found")
)

// CredentialRepository defines the interface for credential repository
type CredentialRepository interface {
	// CreateCredentials creates multiple credentials (requires transaction)
	CreateCredentials(ctx context.Context, tx *sql.Tx, credentials []*domain.Credential) error

	// FindByAccountAndType finds credentials by account ID and type
	FindByAccountAndType(ctx context.Context, accountID string, credType domain.CredentialType) ([]*domain.Credential, error)

	// FindByAccountAndTypes finds credentials by account ID and multiple types in a single query.
	// Returns all matching credentials; callers should filter by type from the result set.
	FindByAccountAndTypes(ctx context.Context, accountID string, credTypes ...domain.CredentialType) ([]*domain.Credential, error)

	// FindByAccountAndTypeTx finds credentials by account ID and type within a transaction.
	// Use this variant inside RunInTransaction to avoid TOCTOU race conditions.
	FindByAccountAndTypeTx(ctx context.Context, tx *sql.Tx, accountID string, credType domain.CredentialType) ([]*domain.Credential, error)

	// FindByTypeAndIdentifier finds a credential by type and identifier (e.g. by email)
	FindByTypeAndIdentifier(ctx context.Context, credType domain.CredentialType, identifier string) (*domain.Credential, error)

	// FindByTypeAndIdentifierTx finds a credential by type and identifier within a transaction.
	// Use this variant inside RunInTransaction to avoid TOCTOU race conditions.
	FindByTypeAndIdentifierTx(ctx context.Context, tx *sql.Tx, credType domain.CredentialType, identifier string) (*domain.Credential, error)

	// FindPasswordCredential finds password credential of an account
	FindPasswordCredential(ctx context.Context, accountID string) (*domain.Credential, error)

	// UpdateCredential updates a credential (requires transaction)
	UpdateCredential(ctx context.Context, tx *sql.Tx, credential *domain.Credential) error

	// UpdateLastUsedAt updates only the last_used_at timestamp of a credential (requires transaction).
	// Use this instead of UpdateCredential when only the last-used time needs to change,
	// to avoid overwriting concurrent modifications to other fields (TOCTOU-safe).
	UpdateLastUsedAt(ctx context.Context, tx *sql.Tx, credentialID string, lastUsedAt time.Time) error

	// SoftDeleteCredentialsByAccount soft deletes all credentials of an account (requires transaction)
	SoftDeleteCredentialsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error

	// SoftDeleteCredential soft deletes a single credential (requires transaction)
	SoftDeleteCredential(ctx context.Context, tx *sql.Tx, credentialID string, deletedAt time.Time) error

	// FindByAccountAndTypeForUpdate finds credentials by account ID and type with row-level locking (requires transaction).
	// Used to prevent concurrent operations (e.g., backup code double-use) via SELECT ... FOR UPDATE.
	FindByAccountAndTypeForUpdate(ctx context.Context, tx *sql.Tx, accountID string, credType domain.CredentialType) ([]*domain.Credential, error)

	// VerifyFirstUnverifiedTOTP atomically verifies the first unverified TOTP credential for an account.
	// Returns true if a credential was verified, false if no pending enrollment was found.
	VerifyFirstUnverifiedTOTP(ctx context.Context, tx *sql.Tx, accountID string) (bool, error)
}
