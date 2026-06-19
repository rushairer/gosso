package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

// rotateAndDeleteScript atomically retrieves and deletes a refresh token in a single Redis operation.
// Returns the token data if it existed (and was deleted), or nil if it was already consumed.
// This prevents TOCTOU race conditions during refresh token rotation.
var rotateAndDeleteScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if data then
    redis.call('DEL', KEYS[1])
end
return data
`)

// rotateTokenScript atomically rotates a refresh token: reads the old token data,
// validates it exists, deletes it, stores the new token, and updates the session index.
// All in a single Lua script to prevent TOCTOU race conditions.
// KEYS[1] = old token key, KEYS[2] = new token key, KEYS[3] = session index key (or "" if no session)
// ARGV[1] = new token JSON, ARGV[2] = expiry seconds, ARGV[3] = old token hash, ARGV[4] = new token hash
// Returns old token data on success, nil if old token not found.
var rotateTokenScript = redis.NewScript(`
local oldData = redis.call('GET', KEYS[1])
if not oldData then
    return nil
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
if KEYS[3] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[3])
    redis.call('SADD', KEYS[3], ARGV[4])
    redis.call('EXPIRE', KEYS[3], ARGV[2])
end
return oldData
`)

// revokeAllSessionScript atomically revokes all refresh tokens under a session:
// reads all token hashes from the session set, deletes each refresh token key,
// and deletes the session set itself — all in a single Lua script to prevent
// TOCTOU race conditions with concurrent RotateRefreshToken calls.
// KEYS[1] = session tokens set key (session_tokens:<sessionID>)
// ARGV[1] = refresh token key prefix (refresh_token:)
// Returns the number of tokens revoked.
var revokeAllSessionScript = redis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
for _, hash in ipairs(members) do
    redis.call('DEL', ARGV[1] .. hash)
end
redis.call('DEL', KEYS[1])
return #members
`)

// RotateRefreshToken rotates refresh tokens atomically.
// The old token is read, deleted, and replaced with a new token in a single Lua script,
// eliminating TOCTOU race conditions between concurrent rotation requests.
//
// NOTE: The pre-read at step 3 retrieves the old token's SessionID before the Lua script
// runs. If a concurrent rotation completes between the pre-read and the script, the
// SessionID used in the script will be stale. This is acceptable because refresh tokens
// are single-use — the Lua script's GET+DEL atomically prevents double-rotation, so the
// concurrent request will fail. The worst case is that the session index update targets
// the wrong session, which is cleaned up by the session expiry mechanism.
func (s *TokenService) RotateRefreshToken(ctx context.Context, oldToken string) (*domain.RefreshToken, error) {
	// 1. Generate new token
	newBytes := make([]byte, refreshTokenLength)
	if _, err := rand.Read(newBytes); err != nil {
		return nil, fmt.Errorf("generate new token: %w", err)
	}
	newTokenString := hex.EncodeToString(newBytes)

	// 2. Build keys and hashes
	oldKey := s.buildRefreshTokenKey(oldToken)
	newHash := domain.HashToken(newTokenString)
	oldHash := domain.HashToken(oldToken)
	newKey := s.buildRefreshTokenKey(newTokenString)
	expirySeconds := int(math.Ceil(s.refreshExpiry.Seconds()))

	// 3. Pre-read old token to get SessionID before running the Lua script.
	//    This enables the session index update to happen atomically inside the script.
	oldData, err := s.redis.Get(ctx, oldKey)
	if err != nil {
		if errors.Is(err, cache.ErrKeyNotFound) {
			return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
		}
		return nil, fmt.Errorf("refresh token lookup failed: %w", err)
	}
	var oldRT domain.RefreshToken
	if err := json.Unmarshal([]byte(oldData), &oldRT); err != nil {
		return nil, fmt.Errorf("unmarshal old refresh token: %w", err)
	}

	// 4. Build session key from the old token's SessionID (empty string if no session)
	sessionKey := ""
	if oldRT.SessionID != "" {
		sessionKey = s.buildSessionTokensKey(oldRT.SessionID)
	}

	// 5. Build new token data with the correct SessionID from the old token
	newRT := &domain.RefreshToken{
		Token:     newTokenString,
		AccountID: oldRT.AccountID,
		ClientID:  oldRT.ClientID,
		SessionID: oldRT.SessionID,
		Scope:     oldRT.Scope,
		IP:        oldRT.IP,
		UserAgent: oldRT.UserAgent,
		ExpiresAt: time.Now().Add(s.refreshExpiry),
		CreatedAt: time.Now(),
	}

	newData, err := json.Marshal(newRT)
	if err != nil {
		return nil, fmt.Errorf("marshal new refresh token: %w", err)
	}

	// 6. Atomically rotate: read old, delete old, store new, update session index.
	//    The Lua script handles session index (SREM/SADD) atomically with the rotation.
	result, err := s.redis.RunScript(ctx, rotateTokenScript,
		[]string{oldKey, newKey, sessionKey},
		newData, expirySeconds, oldHash, newHash,
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionTokenRotate,
		audit.IPFromContext(ctx),
		utility.StringPtr(newRT.AccountID),
		utility.MustMarshalJSON(map[string]any{
			"session_id": newRT.SessionID,
			"old_token":  oldHash,
			"new_token":  newHash,
		}),
		utility.MustMarshalJSON(map[string]any{
			"ip":         audit.IPFromContext(ctx),
			"user_agent": audit.UserAgentFromContext(ctx),
		}),
	))

	return newRT, nil
}

// RevokeRefreshToken revokes a refresh token and removes it from the session index.
func (s *TokenService) RevokeRefreshToken(ctx context.Context, token string) error {
	key := s.buildRefreshTokenKey(token)

	data, err := s.redis.RunScript(ctx, rotateAndDeleteScript, []string{key}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	// Clean up session index
	if dataStr, ok := data.(string); ok && dataStr != "" {
		var rt domain.RefreshToken
		if jsonErr := json.Unmarshal([]byte(dataStr), &rt); jsonErr == nil && rt.SessionID != "" {
			sessionKey := s.buildSessionTokensKey(rt.SessionID)
			tokenHash := domain.HashToken(token)
			if err := s.redis.SRem(ctx, sessionKey, tokenHash); err != nil {
				s.logger.Warn("Failed to remove token hash from session index during revocation", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(rt.SessionID)))
			}
		}

		auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
			auditDomain.ActionTokenRevoke,
			audit.IPFromContext(ctx),
			nil,
			utility.MustMarshalJSON(map[string]any{
				"token_hash": domain.HashToken(token),
				"session_id": rt.SessionID,
			}),
			utility.MustMarshalJSON(map[string]any{
				"ip":         audit.IPFromContext(ctx),
				"user_agent": audit.UserAgentFromContext(ctx),
			}),
		))
	}

	return nil
}

// RevokeAllForSession atomically revokes all refresh tokens under a given session.
// Uses a Lua script to read the session set, delete each refresh token key,
// and delete the session set in a single atomic operation — preventing TOCTOU
// race conditions with concurrent RotateRefreshToken calls.
func (s *TokenService) RevokeAllForSession(ctx context.Context, sessionID string) error {
	sessionKey := s.buildSessionTokensKey(sessionID)

	result, err := s.redis.RunScript(ctx, revokeAllSessionScript,
		[]string{sessionKey},
		refreshTokenKeyPrefix,
	).Int64()
	if err != nil {
		return fmt.Errorf("revoke session tokens: %w", err)
	}

	count := int(result)

	s.logger.Info("Revoked all refresh tokens for session",
		zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Int("count", count))

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionTokenRevoke,
		audit.IPFromContext(ctx),
		nil,
		utility.MustMarshalJSON(map[string]any{
			"session_id": sessionID,
			"reason":     "revoke_all_for_session",
		}),
		utility.MustMarshalJSON(map[string]any{
			"ip":         audit.IPFromContext(ctx),
			"user_agent": audit.UserAgentFromContext(ctx),
		}),
	))

	return nil
}

// RevokeAccessToken blacklists an access token by its JTI so it can no longer be used.
func (s *TokenService) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	if s.blacklist == nil {
		return ErrBlacklistNotConfigured
	}
	return s.blacklist.RevokeToken(ctx, jti, "logout", expiresAt)
}

// RevokeAccountTokens marks all access tokens for the given account as revoked.
// Tokens issued before this call will be rejected by ValidateAccessTokenWithContext.
// The revocation record automatically expires after accessExpiry duration.
func (s *TokenService) RevokeAccountTokens(ctx context.Context, accountID string) error {
	if s.blacklist == nil {
		return ErrBlacklistNotConfigured
	}

	// Double the TTL to ensure the revocation key outlives even the latest-issued token.
	// A token issued at T=(accessExpiry - ε) has IssuedAt near the original expiry;
	// the revocation key must still exist to reject it.
	ttl := s.accessExpiry * 2
	if ttl < MinAccountRevocationTTL {
		ttl = MinAccountRevocationTTL
	}

	err := s.blacklist.SetAccountRevokedAfter(ctx, accountID, time.Now(), ttl)
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionTokenRevoke,
		audit.IPFromContext(ctx),
		utility.StringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{
			"reason": "revoke_all_for_account",
		}),
		utility.MustMarshalJSON(map[string]any{
			"ip":         audit.IPFromContext(ctx),
			"user_agent": audit.UserAgentFromContext(ctx),
		}),
	))

	return nil
}
