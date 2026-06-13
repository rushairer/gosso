package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
)

// IDTokenClaims OIDC ID Token claims
type IDTokenClaims struct {
	jwt.RegisteredClaims
	AZP               string `json:"azp,omitempty"` // Authorized Party — present when aud has a single value
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
	ATHash            string `json:"at_hash,omitempty"`
}

// IDTokenService OIDC ID Token service
type IDTokenService struct {
	tokenSvc       *tokenService.TokenService
	issuer         string
	accountSvc     accountService.AccountService
	credentialRepo accountRepo.CredentialRepository
	expiry         time.Duration
	logger         *zap.Logger
}

const defaultIDTokenExpiry = 10 * time.Minute

// NewIDTokenService creates a new instance of IDTokenService
func NewIDTokenService(
	tokenSvc *tokenService.TokenService,
	issuer string,
	accountSvc accountService.AccountService,
	credentialRepo accountRepo.CredentialRepository,
	expiry time.Duration,
	logger *zap.Logger,
) *IDTokenService {
	logger = utility.EnsureLogger(logger)
	if expiry <= 0 {
		expiry = defaultIDTokenExpiry
	}
	return &IDTokenService{
		tokenSvc:       tokenSvc,
		issuer:         issuer,
		accountSvc:     accountSvc,
		credentialRepo: credentialRepo,
		expiry:         expiry,
		logger:         logger,
	}
}

// GenerateIDToken generates an OIDC ID Token
func (s *IDTokenService) GenerateIDToken(ctx context.Context, accountID, clientID string, scopes []string, nonce string, authTime time.Time, accessToken string) (string, error) {
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
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		AZP:      clientID, // Authorized Party per OIDC Core §2 — single aud value
		Nonce:    nonce,
		AuthTime: ptrInt64(authTime.Unix()),
	}

	// Add claims based on scope
	for _, scope := range scopes {
		switch scope {
		case "profile":
			claims.Name = account.DisplayName
			claims.PreferredUsername = safeString(account.Username)
			claims.Picture = safeString(account.AvatarURL)
			claims.Locale = account.Locale
		case "email":
			if err := s.addEmailClaims(ctx, accountID, claims); err != nil {
				return "", err
			}
		case "phone":
			if err := s.addPhoneClaims(ctx, accountID, claims); err != nil {
				return "", err
			}
		}
	}

	// Compute at_hash: SHA-256 half-hash of access token per OIDC Core §2.3.1
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims.ATHash = base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])
	}

	// Sign the ID Token using TokenService's RSA private key
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.tokenSvc.KeyService().KeyID()
	tokenString, err := token.SignedString(s.tokenSvc.KeyService().PrivateKey())
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}

	return tokenString, nil
}

func (s *IDTokenService) addEmailClaims(ctx context.Context, accountID string, claims *IDTokenClaims) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeEmail)
	if err != nil {
		return fmt.Errorf("query email credential for ID token: %w", err)
	}
	if len(creds) > 0 && creds[0].Identifier != nil {
		claims.Email = *creds[0].Identifier
		verified := creds[0].IsVerified()
		claims.EmailVerified = &verified
	}
	return nil
}

func (s *IDTokenService) addPhoneClaims(ctx context.Context, accountID string, claims *IDTokenClaims) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypePhone)
	if err != nil {
		return fmt.Errorf("query phone credential for ID token: %w", err)
	}
	if len(creds) > 0 && creds[0].Identifier != nil {
		claims.PhoneNumber = *creds[0].Identifier
		verified := creds[0].IsVerified()
		claims.PhoneVerified = &verified
	}
	return nil
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
