package service

import (
	"context"

	"github.com/rushairer/gosso/internal/session/domain"
)

// SessionServiceInterface defines the contract for session management operations.
// Concrete implementation is provided by SessionService.
type SessionServiceInterface interface {
	// CreateSession creates a new session.
	CreateSession(ctx context.Context, session *domain.Session) error

	// GetSession retrieves session information from Redis.
	//
	// IMPORTANT: GetSession does NOT check whether the session has logically
	// expired. Callers that require expiry validation must use ValidateSession.
	GetSession(ctx context.Context, sessionID string) (*domain.Session, error)

	// UpdateSession updates session information atomically.
	UpdateSession(ctx context.Context, session *domain.Session) error

	// DeleteSession deletes a session and removes it from the account session index.
	DeleteSession(ctx context.Context, sessionID string) error

	// RefreshSession refreshes the session expiration.
	RefreshSession(ctx context.Context, sessionID string) error

	// ValidateSession validates whether a session is still active.
	ValidateSession(ctx context.Context, sessionID string) (*domain.Session, error)

	// RevokeSession revokes a specific session (with ownership check).
	RevokeSession(ctx context.Context, accountID string, sessionID string) error

	// RevokeAllForAccount revokes all sessions and tokens for the given account.
	RevokeAllForAccount(ctx context.Context, accountID string) error

	// ListSessionsByAccount lists all active sessions for the given account.
	ListSessionsByAccount(ctx context.Context, accountID string) ([]*domain.Session, error)

	// EnforceSessionLimit ensures that the account does not exceed the maximum
	// number of concurrent sessions.
	EnforceSessionLimit(ctx context.Context, accountID string) error

	// StopCacheCleanup stops the background cache-cleanup goroutine.
	// Call this during graceful shutdown to avoid goroutine leaks.
	StopCacheCleanup()
}
