package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

// createSessionAndTokens creates a session, generates access and refresh tokens.
func (s *AuthService) createSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (retSession *sessionDomain.Session, retAccessToken string, retRefreshToken *tokenDomain.RefreshToken, retErr error) {
	now := time.Now()
	session := &sessionDomain.Session{
		ID:           uuid.New().String(),
		AccountID:    account.ID,
		IP:           ip,
		UserAgent:    userAgent,
		CreatedAt:    now,
		LastActiveAt: now,
	}
	if account.Username != nil {
		session.Username = *account.Username
	}

	if err := s.sessionSvc.CreateSession(ctx, session); err != nil {
		return nil, "", nil, fmt.Errorf("create session: %w", err)
	}

	// Cleanup orphaned session if any subsequent step fails
	defer func() {
		if retErr != nil {
			if delErr := s.sessionSvc.DeleteSession(ctx, session.ID); delErr != nil {
				s.logger.Warn("Failed to cleanup orphaned session",
					zap.String("session_id", utility.MaskOpaqueID(session.ID)), zap.Error(delErr))
			}
		}
	}()

	claims, err := s.buildTokenClaims(ctx, account.ID, session.ID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("build token claims: %w", err)
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID, "")
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate refresh token: %w", err)
	}

	return session, accessToken, refreshToken, nil
}

// CreateSessionAndTokens is the public version of createSessionAndTokens, used by SocialLoginService via SessionTokenCreator interface.
func (s *AuthService) CreateSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
	return s.createSessionAndTokens(ctx, account, ip, userAgent)
}

// loginAuditLogs logs a login success or failure audit record.
func (s *AuthService) loginAuditLogs(ctx context.Context, action string, actor string, accountID *string, detail map[string]any, meta map[string]any) {
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		action,
		actor,
		accountID,
		utility.MustMarshalJSON(detail),
		utility.MustMarshalJSON(meta),
	))
}

// loginAuditLogsSync logs a login failure audit record synchronously for critical security events.
func (s *AuthService) loginAuditLogsSync(ctx context.Context, action string, actor string, accountID *string, detail map[string]any, meta map[string]any) {
	if err := auditService.AuditLogSync(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		action,
		actor,
		accountID,
		utility.MustMarshalJSON(detail),
		utility.MustMarshalJSON(meta),
	)); err != nil {
		s.logger.Error("Failed to write sync audit log", zap.String("action", action), zap.Error(err))
	}
}
