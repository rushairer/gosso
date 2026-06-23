package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

// LockoutStatus represents the current lockout state for an account.
type LockoutStatus struct {
	AccountID  string        `json:"account_id"`
	Username   string        `json:"username"`
	LockedOut  bool          `json:"locked_out"`
	Counters   []LockoutCounter `json:"counters,omitempty"`
}

// LockoutCounter represents a single per-IP rate limit counter for an account.
type LockoutCounter struct {
	Key       string `json:"key"`
	Attempts  int64  `json:"attempts"`
}

// GetLockoutStatus returns the current lockout state for an account by scanning
// Redis for login_attempts:*:{username} keys and reading their values.
func (s *AuthService) GetLockoutStatus(ctx context.Context, accountID string) (*LockoutStatus, error) {
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}

	username := ""
	if account.Username != nil {
		username = strings.ToLower(*account.Username)
	}

	status := &LockoutStatus{
		AccountID: accountID,
		Username:  username,
	}

	if username == "" {
		return status, nil
	}

	// SCAN for per-IP+username rate limit keys.
	pattern := fmt.Sprintf("login_attempts:*:%s", username)
	var cursor uint64
	const maxIterations = 1000
	for i := 0; i < maxIterations; i++ {
		if ctx.Err() != nil {
			break
		}
		keys, nextCursor, err := s.redis.ScanKeys(ctx, cursor, pattern, 100)
		if err != nil {
			s.logger.Warn("Failed to scan lockout keys", zap.Error(err))
			break
		}
		for _, key := range keys {
			val, getErr := s.redis.Get(ctx, key)
			if getErr != nil {
				continue
			}
			count, _ := strconv.ParseInt(val, 10, 64)
			if count > 0 {
				status.LockedOut = true
				status.Counters = append(status.Counters, LockoutCounter{
					Key:      key,
					Attempts: count,
				})
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return status, nil
}

// ClearLockout clears all rate limit counters for the given account.
// Delegates to the existing ClearLoginRateLimitsByUsername.
func (s *AuthService) ClearLockout(ctx context.Context, accountID string) error {
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("find account: %w", err)
	}
	if account.Username == nil {
		return nil
	}
	return s.ClearLoginRateLimitsByUsername(ctx, *account.Username)
}

// Ensure unused imports are consumed.
var _ = utility.MaskOpaqueID
