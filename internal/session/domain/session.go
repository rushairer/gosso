package domain

import (
	"context"
	"time"
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
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	MFAVerified  bool      `json:"mfa_verified"`
	// Metadata stores additional session information (e.g., device type, browser).
	Metadata map[string]any `json:"metadata,omitempty"`
}

// IsExpired reports whether the session has expired.
func (s *Session) IsExpired(ttl time.Duration) bool {
	return time.Since(s.LastActiveAt) > ttl
}

// UpdateActivity updates the last-active timestamp.
func (s *Session) UpdateActivity() {
	s.LastActiveAt = time.Now()
}
