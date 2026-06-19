package domain

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/argon2"

	"github.com/rushairer/gosso/internal/utility"
)

var (
	ErrAccountIDRequired              = errors.New("account ID is required")
	ErrMustUseNewPasswordCredential   = errors.New("must use NewPasswordCredential for password type")
	ErrPasswordRequired               = errors.New("password must not be empty")
	ErrPasswordTooLong                = errors.New("password exceeds maximum length")
	ErrEmailRequired                  = errors.New("email is required")
	ErrInvalidEmailFormat             = errors.New("invalid email format")
	ErrPhoneRequired                  = errors.New("phone is required")
	ErrInvalidPhoneFormat             = errors.New("invalid phone format")
	ErrCredentialAlreadyDeleted       = errors.New("credential is already deleted")
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

// IsValidCredentialType reports whether t is a known credential type.
func IsValidCredentialType(t CredentialType) bool {
	switch t {
	case CredentialTypePassword, CredentialTypeEmail, CredentialTypePhone,
		CredentialTypeTOTP, CredentialTypeWebAuthn, CredentialTypeBackupCode:
		return true
	}
	return false
}

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
	UpdatedAt         time.Time      `json:"updated_at"`
	VerifiedAt        *time.Time     `json:"verified_at,omitempty"`
	LastUsedAt        *time.Time     `json:"last_used_at,omitempty"`
	DeletedAt         *time.Time     `json:"deleted_at,omitempty"`
}

// newBaseCredential creates a Credential with common fields initialized.
// Used internally by all credential constructors.
func newBaseCredential(accountID string, credType CredentialType) *Credential {
	now := time.Now()
	return &Credential{
		ID:        uuid.New().String(),
		AccountID: accountID,
		Type:      credType,
		Verified:  false,
		Metadata:  make(map[string]any),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// NewCredential creates a new credential.
// For password credentials, use NewPasswordCredential instead — this function
// returns an error if called with CredentialTypePassword to prevent accidental plaintext storage.
func NewCredential(accountID string, credType CredentialType, identifier *string, value string) (*Credential, error) {
	if accountID == "" {
		return nil, ErrAccountIDRequired
	}
	if credType == CredentialTypePassword {
		return nil, ErrMustUseNewPasswordCredential
	}
	c := newBaseCredential(accountID, credType)
	c.Identifier = identifier
	c.Value = value
	return c, nil
}

// NewPasswordCredential creates a password credential (auto-hashed).
// The plainPassword must be between 1 and MaxPasswordLength bytes to prevent resource exhaustion.
func NewPasswordCredential(accountID string, plainPassword string) (*Credential, error) {
	if accountID == "" {
		return nil, ErrAccountIDRequired
	}
	if len(plainPassword) == 0 {
		return nil, ErrPasswordRequired
	}
	if len(plainPassword) > utility.MaxPasswordLength {
		return nil, ErrPasswordTooLong
	}
	if err := utility.ValidatePasswordStrength(plainPassword); err != nil {
		return nil, err
	}
	hashedPassword, err := HashPassword(plainPassword)
	if err != nil {
		return nil, err
	}

	c := newBaseCredential(accountID, CredentialTypePassword)
	c.Value = hashedPassword
	c.Verified = true // password credentials are verified at creation
	return c, nil
}

// NewEmailCredential creates an email credential.
// Returns an error if accountID or email is empty or email format is invalid.
func NewEmailCredential(accountID string, email string) (*Credential, error) {
	if accountID == "" {
		return nil, ErrAccountIDRequired
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, ErrEmailRequired
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEmailFormat, err)
	}
	c := newBaseCredential(accountID, CredentialTypeEmail)
	c.Identifier = &email
	return c, nil
}

// NewPhoneCredential creates a phone credential.
// Returns an error if accountID or phone is empty or phone format is invalid.
func NewPhoneCredential(accountID string, phone string) (*Credential, error) {
	if accountID == "" {
		return nil, ErrAccountIDRequired
	}
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return nil, ErrPhoneRequired
	}
	if !utility.ValidatePhoneFormat(phone) {
		return nil, ErrInvalidPhoneFormat
	}
	c := newBaseCredential(accountID, CredentialTypePhone)
	c.Identifier = &phone
	return c, nil
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
// Clears the Value and Identifier fields to avoid retaining sensitive data
// (e.g., password hashes, email addresses, phone numbers) in memory.
func (c *Credential) SoftDelete() error {
	if c.IsDeleted() {
		return ErrCredentialAlreadyDeleted
	}
	now := time.Now()
	c.DeletedAt = &now
	c.UpdatedAt = now
	c.Value = ""
	c.Identifier = nil
	return nil
}

// VerifyPassword verifies the plaintext password against the stored Argon2id hash.
func (c *Credential) VerifyPassword(plainPassword string) bool {
	if c.Type != CredentialTypePassword {
		return false
	}
	return verifyArgon2id(plainPassword, c.Value)
}

// MarshalLogObject implements zapcore.ObjectMarshaler to safely log credentials
// without exposing the Value field (password hash or other sensitive data).
func (c *Credential) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("id", c.ID)
	enc.AddString("account_id", c.AccountID)
	enc.AddString("credential_type", string(c.Type))
	if c.Identifier != nil {
		enc.AddString("identifier", utility.MaskIdentifier(string(c.Type), *c.Identifier))
	}
	enc.AddBool("verified", c.Verified)
	enc.AddBool("primary_credential", c.PrimaryCredential)
	enc.AddTime("created_at", c.CreatedAt)
	enc.AddTime("updated_at", c.UpdatedAt)
	if c.VerifiedAt != nil {
		enc.AddTime("verified_at", *c.VerifiedAt)
	}
	if c.LastUsedAt != nil {
		enc.AddTime("last_used_at", *c.LastUsedAt)
	}
	if c.DeletedAt != nil {
		enc.AddTime("deleted_at", *c.DeletedAt)
	}
	return nil
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
	// Accept current and previous argon2id version for forward compatibility.
	// When the x/crypto library upgrades argon2.Version, existing hashes from
	// the prior version remain verifiable. They will be re-hashed with the new
	// version on next password change.
	if version != argon2.Version && version != argon2.Version-1 {
		return nil, nil, nil, fmt.Errorf("unsupported argon2id version: %d (expected %d or %d)", version, argon2.Version-1, argon2.Version)
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
