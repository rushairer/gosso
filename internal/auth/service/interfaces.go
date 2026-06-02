package service

import (
	"context"
	"time"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// AuthOrchestrator defines the interface used by controllers for authentication operations.
type AuthOrchestrator interface {
	LoginByUsernamePassword(ctx context.Context, req *LoginRequest) (*LoginResult, error)
	LoginByPasskey(ctx context.Context, accountID, ip, userAgent string) (*LoginResult, error)
	VerifyMFALogin(ctx context.Context, mfaToken, mfaCode, mfaType, ip, userAgent string) (*LoginResult, error)
	Logout(ctx context.Context, accountID, sessionID string, accessTokenJTI string, tokenExpiresAt time.Time) error
	RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error)
	ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error)
	ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error)
	RevokeSession(ctx context.Context, accountID, sessionID string) error
	ValidateMFAToken(ctx context.Context, mfaToken string) (*tokenDomain.AccessTokenClaims, error)
	MarkPasskeyMFAVerified(ctx context.Context, accountID string) error
	CompletePasskeyMFALogin(ctx context.Context, mfaToken, ip, userAgent string) (*LoginResult, error)
	MFAService() *MFAService
	PasskeyService() *PasskeyService
}

// TokenManager defines the interface used by controllers and middleware for token operations.
type TokenManager interface {
	GenerateAccessToken(claims *tokenDomain.AccessTokenClaims) (string, error)
	GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*tokenDomain.RefreshToken, error)
	ValidateAccessToken(tokenString string) (*tokenDomain.AccessTokenClaims, error)
	ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*tokenDomain.AccessTokenClaims, error)
	ValidateRefreshToken(ctx context.Context, token string) (*tokenDomain.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldToken string) (*tokenDomain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error)
	AccessExpiry() time.Duration
}

// SessionTokenCreator creates sessions and tokens for authenticated accounts.
// Used by SocialLoginService to share session/token creation logic with AuthService.
type SessionTokenCreator interface {
	CreateSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error)
}

// AccountReader defines the read-only account operations used by controllers.
type AccountReader interface {
	FindAccountByID(ctx context.Context, accountID string) (*accountDomain.Account, error)
	FindAccountByUsername(ctx context.Context, username string) (*accountDomain.Account, error)
}
