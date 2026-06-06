package service

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// LogoutService handles OIDC RP-Initiated Logout operations.
type LogoutService struct {
	tokenSvc   *tokenService.TokenService
	sessionSvc *sessionService.SessionService
	issuer     string
	logger     *zap.Logger
}

// NewLogoutService creates a new LogoutService.
func NewLogoutService(
	tokenSvc *tokenService.TokenService,
	sessionSvc *sessionService.SessionService,
	issuer string,
	logger *zap.Logger,
) *LogoutService {
	return &LogoutService{
		tokenSvc:   tokenSvc,
		sessionSvc: sessionSvc,
		issuer:     issuer,
		logger:     logger,
	}
}

// ValidateIDTokenHint validates an ID token hint per OIDC RP-Initiated Logout spec.
// The OP SHOULD accept expired ID tokens, so expiry is not checked.
// Only signature, issuer, and audience are validated.
func (s *LogoutService) ValidateIDTokenHint(tokenString string) (*IDTokenClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty id_token_hint")
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := &IDTokenClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.tokenSvc.KeyService().PublicKey(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse id_token_hint: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid id_token_hint signature")
	}

	// Manual validation: issuer must match, audience must be non-empty
	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("id_token_hint issuer mismatch: got %q, want %q", claims.Issuer, s.issuer)
	}
	if len(claims.Audience) == 0 {
		return nil, fmt.Errorf("id_token_hint has no audience")
	}

	return claims, nil
}

// LogoutByAccountID revokes all sessions and refresh tokens for the given account.
// Token revocation is handled internally by SessionService.RevokeAllForAccount via its TokenRevoker.
func (s *LogoutService) LogoutByAccountID(ctx context.Context, accountID string) error {
	if s.sessionSvc == nil {
		s.logger.Warn("Session service not available for account logout", zap.String("account_id", accountID))
		return fmt.Errorf("session service not configured")
	}

	if err := s.sessionSvc.RevokeAllForAccount(ctx, accountID); err != nil {
		return fmt.Errorf("revoke all sessions for account: %w", err)
	}

	// Revoke all outstanding access tokens for this account.
	// Uses a "revoke after" timestamp — tokens issued before this time will be
	// rejected by ValidateAccessTokenWithContext.
	if err := s.tokenSvc.RevokeAccountTokens(ctx, accountID); err != nil {
		s.logger.Warn("Failed to revoke access tokens for account during logout",
			zap.String("account_id", accountID), zap.Error(err))
		// Non-fatal: sessions and refresh tokens are already revoked above.
		// The JWT middleware's session check provides a secondary defense.
	}

	s.logger.Info("Account logout successful", zap.String("account_id", accountID))
	return nil
}

// LogoutBySessionID deletes a single session and revokes its refresh tokens.
func (s *LogoutService) LogoutBySessionID(ctx context.Context, accountID, sessionID string) error {
	if s.sessionSvc == nil {
		s.logger.Warn("Session service not available for session logout", zap.String("session_id", sessionID))
		return fmt.Errorf("session service not configured")
	}

	if err := s.tokenSvc.RevokeAllForSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to revoke tokens for session during logout",
			zap.String("session_id", sessionID), zap.Error(err))
	}

	if err := s.sessionSvc.RevokeSession(ctx, accountID, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	s.logger.Info("Session logout successful",
		zap.String("account_id", accountID), zap.String("session_id", sessionID))
	return nil
}
