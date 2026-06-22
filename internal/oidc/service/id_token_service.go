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
	AZP               string   `json:"azp,omitempty"` // Authorized Party — present when aud has a single value
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     *bool    `json:"email_verified,omitempty"`
	PhoneNumber       string   `json:"phone_number,omitempty"`
	PhoneVerified     *bool    `json:"phone_number_verified,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	AuthTime          *int64   `json:"auth_time,omitempty"`
	AMR               []string `json:"amr,omitempty"` // Authentication Methods References (e.g. ["pwd"], ["pwd","otp"], ["swk"])
	ATHash            string   `json:"at_hash,omitempty"`
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

// GenerateIDToken generates an OIDC ID Token.
// authMethods contains AMR values per RFC 8176 (e.g. "pwd", "otp", "swk").
// Pass nil to omit the amr claim.
func (s *IDTokenService) GenerateIDToken(ctx context.Context, accountID, clientID string, scopes []string, nonce string, authTime time.Time, accessToken string, authMethods []string) (string, error) {
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
		AuthTime: utility.Ptr[int64](authTime.Unix()),
		AMR:      authMethods,
	}

	// Add claims based on scope
	// Batch email+phone credential queries into a single DB round-trip when both are needed.
	needEmail, needPhone := false, false
	for _, scope := range scopes {
		switch scope {
		case "profile":
			claims.Name = account.DisplayName
			claims.PreferredUsername = utility.DerefString(account.Username)
			claims.Picture = utility.DerefString(account.AvatarURL)
			claims.Locale = account.Locale
		case "email":
			needEmail = true
		case "phone":
			needPhone = true
		}
	}
	if needEmail || needPhone {
		if contactErr := s.addContactClaims(ctx, accountID, claims, needEmail, needPhone); contactErr != nil {
			return "", contactErr
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

// addContactClaims fetches email and/or phone credentials in a single DB query
// and populates the corresponding claims on the ID token.
func (s *IDTokenService) addContactClaims(ctx context.Context, accountID string, claims *IDTokenClaims, needEmail, needPhone bool) error {
	var credTypes []accountDomain.CredentialType
	if needEmail {
		credTypes = append(credTypes, accountDomain.CredentialTypeEmail)
	}
	if needPhone {
		credTypes = append(credTypes, accountDomain.CredentialTypePhone)
	}

	creds, err := s.credentialRepo.FindByAccountAndTypes(ctx, accountID, credTypes...)
	if err != nil {
		return fmt.Errorf("query contact credentials for ID token: %w", err)
	}

	for _, c := range creds {
		if c.Identifier == nil {
			continue
		}
		switch c.Type {
		case accountDomain.CredentialTypeEmail:
			claims.Email = *c.Identifier
			verified := c.IsVerified()
			claims.EmailVerified = &verified
		case accountDomain.CredentialTypePhone:
			claims.PhoneNumber = *c.Identifier
			verified := c.IsVerified()
			claims.PhoneVerified = &verified
		case accountDomain.CredentialTypePassword,
			accountDomain.CredentialTypeTOTP,
			accountDomain.CredentialTypeWebAuthn,
			accountDomain.CredentialTypeBackupCode:
			// These credential types are not contact-related; skip.
		}
	}
	return nil
}
