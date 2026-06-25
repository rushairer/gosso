package service

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. Validate old refresh token (read-only, no rotation)
	oldRT, err := s.tokenSvc.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		s.logger.Debug("Refresh token validation failed", zap.Error(err))
		return nil, ErrInvalidRefreshToken
	}

	// 2. Verify IP binding — reject refresh from a different IP to prevent token theft.
	// NOTE: If the token was generated without an IP (oldRT.IP == ""), the check is skipped.
	// This is a known degradation path: if an upstream middleware failure causes IP loss at
	// token creation time, the resulting token will never be IP-protected. In production,
	// enable AuthConfig.EnforceIPBinding to reject token creation when IP is unavailable.
	if oldRT.IP != "" {
		currentIP := audit.IPFromContext(ctx)
		if currentIP == "" {
			s.logger.Warn("Refresh token has IP binding but current request has no IP; rejecting",
				zap.String("account_id", utility.MaskOpaqueID(oldRT.AccountID)))
			return nil, ErrInvalidRefreshToken
		} else if utility.NormalizeIP(oldRT.IP) != utility.NormalizeIP(currentIP) {
			s.logger.Warn("Refresh token IP mismatch",
				zap.String("original_ip", utility.MaskOpaqueID(oldRT.IP)),
				zap.String("current_ip", utility.MaskOpaqueID(currentIP)),
				zap.String("account_id", utility.MaskOpaqueID(oldRT.AccountID)))
			return nil, ErrInvalidRefreshToken
		}
	}

	// 3. Validate session BEFORE rotation (prevents orphaned token on failure).
	// Skip session validation when SessionID is empty — this happens for OIDC
	// tokens that don't carry a session binding. The JWT auth middleware already
	// permits SessionID="" (skips session check), so the refresh flow must be
	// consistent: an OIDC token that works as an access token must also be refreshable.
	sessionID := oldRT.SessionID
	if sessionID != "" {
		_, err := s.sessionSvc.ValidateSession(ctx, sessionID)
		if err != nil {
			s.logger.Debug("Session validation failed during token refresh", zap.Error(err))
			return nil, ErrSessionInvalid
		}
	} else {
		s.logger.Debug("Refresh token has no session binding; skipping session validation",
			zap.String("account_id", utility.MaskOpaqueID(oldRT.AccountID)))
	}

	// 4 & 5. Validate account and build token claims in parallel — neither depends on the other.
	var account *accountDomain.Account
	var claims *tokenDomain.AccessTokenClaims
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var findErr error
		account, findErr = s.accountSvc.FindAccountByID(gctx, oldRT.AccountID)
		if findErr != nil || account == nil || !account.IsActive() {
			return accountService.ErrAccountNotActive
		}
		return nil
	})

	g.Go(func() error {
		var buildErr error
		claims, buildErr = s.buildTokenClaims(gctx, oldRT.AccountID, sessionID)
		if buildErr != nil {
			return fmt.Errorf("build token claims: %w", buildErr)
		}
		return nil
	})

	if waitErr := g.Wait(); waitErr != nil {
		return nil, waitErr
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 6. Rotate refresh token (old token deleted from Redis)
	newRefreshToken, err := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if err != nil {
		s.logger.Debug("Refresh token rotation failed", zap.Error(err))
		return nil, ErrInvalidRefreshToken
	}

	// 7. Refresh session TTL (best-effort). If this fails the new tokens are
	// still valid and usable, but the session may expire sooner than expected.
	// Skip for session-less tokens (OIDC flow with empty SessionID).
	sessionRefreshOK := true
	if sessionID != "" {
		if err := s.sessionSvc.RefreshSession(ctx, sessionID); err != nil {
			sessionRefreshOK = false
			s.logger.Warn("Failed to refresh session; tokens are still valid but session may expire early",
				zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		}
	}

	return &RefreshResult{
		AccessToken:          accessToken,
		RefreshToken:         newRefreshToken.Token,
		SessionID:            sessionID,
		SessionRefreshFailed: !sessionRefreshOK,
	}, nil
}

// ValidateSession validates the session
func (s *AuthService) ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error) {
	return s.sessionSvc.ValidateSession(ctx, sessionID)
}

// ListSessions lists all active sessions for the account
func (s *AuthService) ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error) {
	return s.sessionSvc.ListSessionsByAccount(ctx, accountID)
}

// RevokeSession revokes specified session
func (s *AuthService) RevokeSession(ctx context.Context, accountID, sessionID string) error {
	return s.sessionSvc.RevokeSession(ctx, accountID, sessionID)
}
