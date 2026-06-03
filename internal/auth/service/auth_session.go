package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
)

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. Validate old refresh token (read-only, no rotation)
	oldRT, err := s.tokenSvc.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	}

	// 2. Validate session BEFORE rotation (prevents orphaned token on failure)
	sessionID, err := uuid.Parse(oldRT.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSessionID, err)
	}
	session, err := s.sessionSvc.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}

	// 3. Validate account BEFORE rotation
	account, err := s.accountSvc.FindAccountByID(ctx, oldRT.AccountID)
	if err != nil || account == nil || account.Status != accountDomain.AccountStatusActive {
		return nil, ErrAccountNotActive
	}

	// 4. Rotate refresh token (session + account already validated)
	newRefreshToken, err := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	}

	// 5. Build claims and generate new access token
	claims, err := s.buildTokenClaims(ctx, newRefreshToken.AccountID, session.ID.String())
	if err != nil {
		return nil, fmt.Errorf("build token claims: %w", err)
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 6. Refresh session
	if err := s.sessionSvc.RefreshSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to refresh session", zap.Error(err), zap.String("session_id", sessionID.String()))
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

// ValidateSession validates the session
func (s *AuthService) ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error) {
	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session id: %w", err)
	}
	return s.sessionSvc.ValidateSession(ctx, parsedID)
}

// ListSessions lists all active sessions for the account
func (s *AuthService) ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error) {
	return s.sessionSvc.ListSessionsByAccount(ctx, accountID)
}

// RevokeSession revokes specified session
func (s *AuthService) RevokeSession(ctx context.Context, accountID, sessionID string) error {
	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}
	return s.sessionSvc.RevokeSession(ctx, accountID, parsedID)
}
