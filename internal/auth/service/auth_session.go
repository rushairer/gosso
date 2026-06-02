package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
)

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. Verify and rotate Refresh Token
	newRefreshToken, err := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	}

	// 2. Verify if the session is still active
	sessionID, err := uuid.Parse(newRefreshToken.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSessionID, err)
	}
	session, err := s.sessionSvc.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}

	// 3. Build claims and generate new access token
	claims, err := s.buildTokenClaims(ctx, newRefreshToken.AccountID, session.ID.String())
	if err != nil {
		return nil, fmt.Errorf("build token claims: %w", err)
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 4. Refresh session
	_ = s.sessionSvc.RefreshSession(ctx, sessionID)

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
