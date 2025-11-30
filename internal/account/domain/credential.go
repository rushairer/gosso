package domain

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// CredentialType 凭证类型
type CredentialType string

const (
	CredentialTypePassword   CredentialType = "password"
	CredentialTypeEmail      CredentialType = "email"
	CredentialTypePhone      CredentialType = "phone"
	CredentialTypeTOTP       CredentialType = "totp"
	CredentialTypeWebAuthn   CredentialType = "webauthn"
	CredentialTypeBackupCode CredentialType = "backup_code"
)

// Credential 凭证领域模型
type Credential struct {
	ID                string                 `json:"id"`
	AccountID         string                 `json:"account_id"`
	Type              CredentialType         `json:"credential_type"`
	Identifier        *string                `json:"identifier,omitempty"`
	Value             string                 `json:"-"` // 不序列化到 JSON（安全）
	Verified          bool                   `json:"verified"`
	PrimaryCredential bool                   `json:"primary_credential"`
	Metadata          map[string]any `json:"metadata"`
	CreatedAt         time.Time              `json:"created_at"`
	VerifiedAt        *time.Time             `json:"verified_at,omitempty"`
	LastUsedAt        *time.Time             `json:"last_used_at,omitempty"`
	DeletedAt         *time.Time             `json:"deleted_at,omitempty"`
}

// NewCredential 创建新凭证
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

// NewPasswordCredential 创建密码凭证（自动哈希）
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
		Verified:  true, // 密码凭证创建时即为已验证
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
	}, nil
}

// NewEmailCredential 创建邮箱凭证
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

// NewPhoneCredential 创建手机凭证
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

// IsDeleted 是否已软删除
func (c *Credential) IsDeleted() bool {
	return c.DeletedAt != nil
}

// IsVerified 是否已验证
func (c *Credential) IsVerified() bool {
	return c.Verified
}

// Verify 标记为已验证
func (c *Credential) Verify() {
	now := time.Now()
	c.Verified = true
	c.VerifiedAt = &now
}

// MarkUsed 更新最后使用时间
func (c *Credential) MarkUsed() {
	now := time.Now()
	c.LastUsedAt = &now
}

// SoftDelete 软删除凭证
func (c *Credential) SoftDelete() {
	now := time.Now()
	c.DeletedAt = &now
}

// VerifyPassword 验证密码（仅用于密码类型凭证）
func (c *Credential) VerifyPassword(plainPassword string) bool {
	if c.Type != CredentialTypePassword {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.Value), []byte(plainPassword)) == nil
}

// HashPassword 哈希密码
func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}
