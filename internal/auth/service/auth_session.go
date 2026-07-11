package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	"github.com/rushairer/gosso/internal/cache"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	refreshTokenLockPrefix      = "auth_refresh_lock:"
	refreshTokenLockTTL         = 30 * time.Second
	refreshTokenLockWaitTimeout = 5 * time.Second
	refreshTokenLockPoll        = 25 * time.Millisecond
)

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	return s.withRefreshTokenLock(ctx, refreshToken, func() (*RefreshResult, error) {
		return s.refreshTokensLocked(ctx, refreshToken)
	})
}

func (s *AuthService) refreshTokensLocked(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. Validate old refresh token (read-only, no rotation)
	oldRT, replayedRotation, err := s.loadRefreshTokenForRefresh(ctx, refreshToken)
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
		_, sessionErr := s.sessionSvc.ValidateSession(ctx, sessionID)
		if sessionErr != nil {
			s.logger.Debug("Session validation failed during token refresh", zap.Error(sessionErr))
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

	claims.ClientID = oldRT.ClientID
	if oldRT.Scope != "" {
		claims.Scope = oldRT.Scope
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 6. Refresh session activity before token rotation. A successful refresh
	// response must mean the backing session is still active and has been
	// extended; otherwise the caller would receive fresh tokens bound to a
	// session that may immediately fail validation.
	if sessionID != "" {
		if err := s.sessionSvc.RefreshSession(ctx, sessionID); err != nil {
			s.logger.Debug("Session refresh failed during token refresh",
				zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
			return nil, ErrSessionInvalid
		}
	}

	newRefreshToken := oldRT
	if !replayedRotation {
		// 7. Rotate refresh token (old token deleted from Redis)
		var rotateErr error
		newRefreshToken, rotateErr = s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
		if rotateErr != nil {
			s.logger.Debug("Refresh token rotation failed", zap.Error(rotateErr))
			return nil, ErrInvalidRefreshToken
		}
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
		SessionID:    sessionID,
	}, nil
}

func (s *AuthService) loadRefreshTokenForRefresh(ctx context.Context, refreshToken string) (*tokenDomain.RefreshToken, bool, error) {
	rt, err := s.tokenSvc.ValidateRefreshToken(ctx, refreshToken)
	if err == nil {
		return rt, false, nil
	}
	if !errors.Is(err, cache.ErrKeyNotFound) {
		return nil, false, err
	}

	replayedRT, replayErr := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if replayErr != nil {
		return nil, false, err
	}
	return replayedRT, true, nil
}

func refreshTokenHashPrefix(refreshToken string) string {
	if refreshToken == "" {
		return ""
	}
	hash := tokenDomain.HashToken(refreshToken)
	if len(hash) > 16 {
		return hash[:16]
	}
	return hash
}

func (s *AuthService) withRefreshTokenLock(ctx context.Context, refreshToken string, fn func() (*RefreshResult, error)) (*RefreshResult, error) {
	if s.redis == nil || refreshToken == "" {
		return fn()
	}

	lockKey := refreshTokenLockPrefix + refreshTokenHashPrefix(refreshToken)
	deadline := time.Now().Add(refreshTokenLockWaitTimeout)
	for {
		acquired, err := s.redis.SetNX(ctx, lockKey, "1", refreshTokenLockTTL)
		if err != nil {
			s.logger.Warn("Failed to acquire refresh token lock",
				zap.Error(err),
				zap.String("refresh_token_hash", refreshTokenHashPrefix(refreshToken)))
			return nil, err
		}
		if acquired {
			result, fnErr := fn()
			if deleteErr := s.redis.Del(context.Background(), lockKey); deleteErr != nil {
				s.logger.Warn("Failed to release refresh token lock",
					zap.Error(deleteErr),
					zap.String("refresh_token_hash", refreshTokenHashPrefix(refreshToken)))
			}
			return result, fnErr
		}

		if time.Now().After(deadline) {
			s.logger.Warn("Timed out waiting for refresh token lock",
				zap.String("refresh_token_hash", refreshTokenHashPrefix(refreshToken)))
			return nil, ErrInvalidRefreshToken
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(refreshTokenLockPoll):
		}
	}
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
