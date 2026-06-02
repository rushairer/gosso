package domain

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
func NewCredential(accountID string, credType CredentialType, identifier *string, value string) *Credential {
	return &Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       credType,
		Identifier: identifier,
		Value:      value,
		Verified:   false,
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
	}
}

// NewPasswordCredential creates a password credential (auto-hashed).
func NewPasswordCredential(accountID string, plainPassword string) (*Credential, error) {
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
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
	}, nil
}

// NewEmailCredential creates an email credential.
func NewEmailCredential(accountID string, email string) *Credential {
	return &Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       CredentialTypeEmail,
		Identifier: &email,
		Verified:   false,
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
	}
}

// NewPhoneCredential creates a phone credential.
func NewPhoneCredential(accountID string, phone string) *Credential {
	return &Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       CredentialTypePhone,
		Identifier: &phone,
		Verified:   false,
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
	}
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

// SoftDelete soft-deletes the credential.
func (c *Credential) SoftDelete() {
	now := time.Now()
	c.DeletedAt = &now
}

// VerifyPassword verifies the plaintext password (password credentials only).
func (c *Credential) VerifyPassword(plainPassword string) bool {
	if c.Type != CredentialTypePassword {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.Value), []byte(plainPassword)) == nil
}

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}
