package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"go.uber.org/zap"
)

// IDTokenClaims OIDC ID Token 声明
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	PhoneNumber       string `json:"phone_number,omitempty"`
	PhoneVerified     *bool  `json:"phone_number_verified,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	AuthTime          *int64 `json:"auth_time,omitempty"`
}

// IDTokenService OIDC ID Token 服务
type IDTokenService struct {
	tokenSvc      *tokenService.TokenService
	issuer        string
	accountSvc    accountService.AccountService
	credentialRepo accountRepo.CredentialRepository
	logger        *zap.Logger
}

// NewIDTokenService 创建 ID Token 服务实例
func NewIDTokenService(
	tokenSvc *tokenService.TokenService,
	issuer string,
	accountSvc accountService.AccountService,
	credentialRepo accountRepo.CredentialRepository,
	logger *zap.Logger,
) *IDTokenService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &IDTokenService{
		tokenSvc:      tokenSvc,
		issuer:        issuer,
		accountSvc:    accountSvc,
		credentialRepo: credentialRepo,
		logger:        logger,
	}
}

// GenerateIDToken 生成 OIDC ID Token
func (s *IDTokenService) GenerateIDToken(ctx context.Context, accountID, clientID string, scopes []string, nonce string, authTime time.Time) (string, error) {
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return "", fmt.Errorf("find account: %w", err)
	}

	now := time.Now()
	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   accountID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        accountID,
		},
		Sub:      accountID,
		Nonce:    nonce,
		AuthTime: ptrInt64(authTime.Unix()),
	}

	// 根据 scope 添加声明
	for _, scope := range scopes {
		switch scope {
		case "profile":
			claims.Name = account.DisplayName
			claims.PreferredUsername = safeString(account.Username)
			claims.Picture = safeString(account.AvatarURL)
			claims.Locale = account.Locale
		case "email":
			s.addEmailClaims(ctx, accountID, claims)
		case "phone":
			s.addPhoneClaims(ctx, accountID, claims)
		}
	}

	// 使用 TokenService 的 RSA 私钥签发 ID Token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.tokenSvc.KeyService().KeyID()
	tokenString, err := token.SignedString(s.tokenSvc.KeyService().PrivateKey())
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}

	return tokenString, nil
}

func (s *IDTokenService) addEmailClaims(ctx context.Context, accountID string, claims *IDTokenClaims) {
	cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, accountDomain.CredentialTypeEmail, "")
	if err == nil && cred.AccountID == accountID && cred.Identifier != nil {
		claims.Email = *cred.Identifier
		verified := cred.IsVerified()
		claims.EmailVerified = &verified
	}
}

func (s *IDTokenService) addPhoneClaims(ctx context.Context, accountID string, claims *IDTokenClaims) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypePhone)
	if err == nil && len(creds) > 0 && creds[0].Identifier != nil {
		claims.PhoneNumber = *creds[0].Identifier
		verified := creds[0].IsVerified()
		claims.PhoneVerified = &verified
	}
}

func ptrInt64(v int64) *int64 {
	return &v
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
