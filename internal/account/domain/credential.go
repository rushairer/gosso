package domain

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// CredentialType represents the type of credential.
type CredentialType string

const (
	CredentialTypePassword   CredentialType = "password"
	CredentialTypeEmail      CredentialType = "email"
	CredentialTypePhone      CredentialType = "phone"
	CredentialTypeTOTP       CredentialType = "totp"
	CredentialTypeWebAuthn   CredentialType = "webauthn"
	CredentialTypeBackupCode CredentialType = "backup_code"

	// Argon2id parameters (OWASP 2023 recommendation for server-side hashing).
	Argon2Time    = 1         // iterations
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4         // parallelism
	Argon2SaltLen = 16        // bytes
	Argon2KeyLen  = 32        // bytes
)

// Credential is the credential domain model.
type Credential struct {
	ID                string         `json:"id"`
	AccountID         string         `json:"account_id"`
	Type              CredentialType `json:"credential_type"`
	Identifier        *string        `json:"identifier,omitempty"`
	Value             string         `json:"-"` // excluded from JSON serialization (security).
	Verified          bool           `json:"verified"`
	PrimaryCredential bool           `json:"primary_credential"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         time.Time      `json:"created_at"`
	VerifiedAt        *time.Time     `json:"verified_at,omitempty"`
	LastUsedAt        *time.Time     `json:"last_used_at,omitempty"`
	DeletedAt         *time.Time     `json:"deleted_at,omitempty"`
}

// NewCredential creates a new credential.
// For password credentials, use NewPasswordCredential instead — this function
// returns an error if called with CredentialTypePassword to prevent accidental plaintext storage.
func NewCredential(accountID string, credType CredentialType, identifier *string, value string) (*Credential, error) {
	if accountID == "" {
		return nil, errors.New("account ID is required")
	}
	if credType == CredentialTypePassword {
		return nil, fmt.Errorf("NewCredential must not be used with CredentialTypePassword; use NewPasswordCredential instead")
	}
	return &Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       credType,
		Identifier: identifier,
		Value:      value,
		Verified:   false,
		Metadata:   make(map[string]any),
		CreatedAt:  time.Now(),
	}, nil
}

// NewPasswordCredential creates a password credential (auto-hashed).
// The plainPassword must be between 1 and 1024 bytes to prevent resource exhaustion.
func NewPasswordCredential(accountID string, plainPassword string) (*Credential, error) {
	if accountID == "" {
		return nil, errors.New("account ID is required")
	}
	if len(plainPassword) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if len(plainPassword) > 1024 {
		return nil, fmt.Errorf("password must not exceed 1024 bytes")
	}
	hashedPassword, err := HashPassword(plainPassword)
	if err != nil {
		return nil, err
	}

	return &Credential{
		ID:        uuid.New().String(),
		AccountID: accountID,
		Type:      CredentialTypePassword,
		Value:     hashedPassword,
		Verified:  true, // password credentials are verified at creation
		Metadata:  make(map[string]any),
		CreatedAt: time.Now(),
	}, nil
}

// NewEmailCredential creates an email credential.
// Returns an error if accountID or email is empty.
func NewEmailCredential(accountID string, email string) (*Credential, error) {
	if accountID == "" {
		return nil, errors.New("account ID is required")
	}
	if email == "" {
		return nil, errors.New("email is required")
	}
	return &Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       CredentialTypeEmail,
		Identifier: &email,
		Verified:   false,
		Metadata:   make(map[string]any),
		CreatedAt:  time.Now(),
	}, nil
}

// NewPhoneCredential creates a phone credential.
// Returns an error if accountID or phone is empty.
func NewPhoneCredential(accountID string, phone string) (*Credential, error) {
	if accountID == "" {
		return nil, errors.New("account ID is required")
	}
	if phone == "" {
		return nil, errors.New("phone is required")
	}
	return &Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       CredentialTypePhone,
		Identifier: &phone,
		Verified:   false,
		Metadata:   make(map[string]any),
		CreatedAt:  time.Now(),
	}, nil
}

// IsDeleted reports whether the credential has been soft-deleted.
func (c *Credential) IsDeleted() bool {
	return c.DeletedAt != nil
}

// IsVerified reports whether the credential has been verified.
func (c *Credential) IsVerified() bool {
	return c.Verified
}

// Verify marks the credential as verified.
func (c *Credential) Verify() {
	now := time.Now()
	c.Verified = true
	c.VerifiedAt = &now
}

// MarkUsed updates the last-used timestamp.
func (c *Credential) MarkUsed() {
	now := time.Now()
	c.LastUsedAt = &now
}

// SoftDelete soft-deletes the credential. Returns an error if already deleted.
func (c *Credential) SoftDelete() error {
	if c.IsDeleted() {
		return errors.New("credential is already deleted")
	}
	now := time.Now()
	c.DeletedAt = &now
	return nil
}

// VerifyPassword verifies the plaintext password against the stored Argon2id hash.
func (c *Credential) VerifyPassword(plainPassword string) bool {
	if c.Type != CredentialTypePassword {
		return false
	}
	return verifyArgon2id(plainPassword, c.Value)
}

// HashPassword hashes a plaintext password using Argon2id with PHC format encoding.
// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt_b64>$<hash_b64>
func HashPassword(password string) (string, error) {
	salt := make([]byte, Argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		Argon2Memory, Argon2Time, Argon2Threads, saltB64, hashB64), nil
}

// verifyArgon2id parses a PHC-encoded argon2id hash and verifies the password.
func verifyArgon2id(password, encodedHash string) bool {
	p, salt, hash, err := parseArgon2idHash(encodedHash)
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(hash)))
	return subtle.ConstantTimeCompare(computedHash, hash) == 1
}

type argon2idParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

// parseArgon2idHash decodes a PHC-formatted argon2id hash string.
func parseArgon2idHash(encodedHash string) (*argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid argon2id hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("not an argon2id hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("unsupported argon2id version: %d", version)
	}

	p := &argon2idParams{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid argon2id params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash encoding: %w", err)
	}

	return p, salt, hash, nil
}
