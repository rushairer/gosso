package service

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
)

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. Validate old refresh token (read-only, no rotation)
	oldRT, err := s.tokenSvc.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRefreshToken, err)
	}

	// 2. Verify IP binding — reject refresh from a different IP to prevent token theft
	if oldRT.IP != "" {
		currentIP := audit.IPFromContext(ctx)
		if currentIP == "" {
			s.logger.Warn("Refresh token has IP binding but current request has no IP; rejecting",
				zap.String("account_id", oldRT.AccountID))
			return nil, ErrInvalidRefreshToken
		} else if oldRT.IP != currentIP {
			s.logger.Warn("Refresh token IP mismatch",
				zap.String("original_ip", oldRT.IP),
				zap.String("current_ip", currentIP),
				zap.String("account_id", oldRT.AccountID))
			return nil, ErrInvalidRefreshToken
		}
	}

	// 3. Validate session BEFORE rotation (prevents orphaned token on failure)
	sessionID := oldRT.SessionID
	session, err := s.sessionSvc.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSessionInvalid, err)
	}

	// 4. Validate account BEFORE rotation
	account, err := s.accountSvc.FindAccountByID(ctx, oldRT.AccountID)
	if err != nil || account == nil || account.Status != accountDomain.AccountStatusActive {
		return nil, accountService.ErrAccountNotActive
	}

	// 5. Build claims and generate new access token BEFORE rotating refresh token.
	// If access token generation fails, the old refresh token remains valid so the
	// client can retry instead of being locked out.
	claims, err := s.buildTokenClaims(ctx, oldRT.AccountID, session.ID)
	if err != nil {
		return nil, fmt.Errorf("build token claims: %w", err)
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 6. Rotate refresh token (old token deleted from Redis)
	newRefreshToken, err := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRefreshToken, err)
	}

	// 7. Refresh session
	if err := s.sessionSvc.RefreshSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to refresh session", zap.Error(err), zap.String("session_id", sessionID))
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
		SessionID:    session.ID,
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
