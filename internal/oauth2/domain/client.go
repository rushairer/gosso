package domain

import (
	"crypto/subtle"
	"fmt"
	"slices"
	"time"
)

// OAuth2Client OAuth2 客户端实体
type OAuth2Client struct {
	ID               string         `json:"id"`
	AccountID        string         `json:"account_id"`
	ClientID         string         `json:"client_id"`
	ClientSecretHash string         `json:"-"` // 仅在 confidential 客户端时有值
	Name             string         `json:"name"`
	Description      string         `json:"description,omitempty"`
	RedirectURIs     []string       `json:"redirect_uris"`
	GrantTypes       []string       `json:"grant_types"`
	Scopes           []string       `json:"scopes"`
	IsConfidential   bool           `json:"is_confidential"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        *time.Time     `json:"deleted_at,omitempty"`
}

// ValidateRedirectURI 验证重定向 URI 是否在注册列表中
func (c *OAuth2Client) ValidateRedirectURI(uri string) bool {
	for _, registered := range c.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(uri), []byte(registered)) == 1 {
			return true
		}
	}
	return false
}

// HasGrantType 检查是否支持指定的授权类型
func (c *OAuth2Client) HasGrantType(gt string) bool {
	return slices.Contains(c.GrantTypes, gt)
}

// ValidateScope 验证并返回客户端支持的 scope 子集
func (c *OAuth2Client) ValidateScope(requestedScopes []string) []string {
	var valid []string
	for _, s := range requestedScopes {
		if slices.Contains(c.Scopes, s) {
			valid = append(valid, s)
		}
	}
	return valid
}

// VerifySecret 验证客户端密钥（通过 bcrypt 验证）
func (c *OAuth2Client) VerifySecret(secret string, verifyFn func(hashed, plain string) bool) bool {
	if !c.IsConfidential || c.ClientSecretHash == "" {
		return false
	}
	return verifyFn(c.ClientSecretHash, secret)
}

// Grant Type 常量
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

// 错误定义
var (
	ErrClientNotFound       = fmt.Errorf("oauth2 client not found")
	ErrInvalidRedirectURI   = fmt.Errorf("invalid redirect_uri")
	ErrUnsupportedGrantType = fmt.Errorf("unsupported grant type")
	ErrInvalidScope         = fmt.Errorf("invalid scope")
	ErrClientSecretMismatch = fmt.Errorf("client secret mismatch")
)
