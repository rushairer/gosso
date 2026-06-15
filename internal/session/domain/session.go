package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SessionValidator checks whether a session is still active.
type SessionValidator interface {
	ValidateSession(ctx context.Context, sessionID string) (*Session, error)
}

// Session is the session entity.
type Session struct {
	ID           string    `json:"id"`
	AccountID    string    `json:"account_id"`
	Username     string    `json:"username,omitempty"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	MFAVerified  bool      `json:"mfa_verified"`
	Valid        bool      `json:"valid"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	// Metadata stores additional session information (e.g., device type, browser).
	Metadata map[string]any `json:"metadata,omitempty"`
}

// NewSession creates a new session with the given parameters.
func NewSession(accountID, username, ip, userAgent string, mfaVerified bool) *Session {
	now := time.Now()
	return &Session{
		ID:           uuid.New().String(),
		AccountID:    accountID,
		Username:     username,
		IP:           ip,
		UserAgent:    userAgent,
		MFAVerified:  mfaVerified,
		Valid:        true,
		CreatedAt:    now,
		LastActiveAt: now,
		Metadata:     make(map[string]any),
	}
}

// IsExpired reports whether the session has expired.
func (s *Session) IsExpired(ttl time.Duration) bool {
	return time.Since(s.LastActiveAt) > ttl
}

// UpdateActivity updates the last-active timestamp.
func (s *Session) UpdateActivity() {
	s.LastActiveAt = time.Now()
}

// Invalidate marks the session as invalid.
func (s *Session) Invalidate() {
	s.Valid = false
}
