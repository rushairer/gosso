package domain

import (
	"time"

	"github.com/google/uuid"
)

// Session 会话实体
type Session struct {
	ID           uuid.UUID `json:"id"`
	AccountID    uuid.UUID `json:"account_id"`
	Username     string    `json:"username,omitempty"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	MFAVerified  bool      `json:"mfa_verified"`
	// Metadata 存储额外的会话信息（如设备类型、浏览器等）
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsExpired 检查会话是否已过期
func (s *Session) IsExpired(ttl time.Duration) bool {
	return time.Since(s.LastActiveAt) > ttl
}

// UpdateActivity 更新最后活跃时间
func (s *Session) UpdateActivity() {
	s.LastActiveAt = time.Now()
}
