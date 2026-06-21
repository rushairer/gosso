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

// rotateTokenScript atomically reads and deletes the old refresh token, then
// updates the session index (SREM old hash, SADD new hash) in a single Lua script.
// The session ID is parsed from the old token JSON inside the script, eliminating
// the need for a separate pre-read round-trip in Go.
// KEYS[1] = old token key
// ARGV[1] = old token hash, ARGV[2] = new token hash, ARGV[3] = session key prefix,
// ARGV[4] = expiry seconds (for session key TTL)
// Returns old token data on success, nil if old token not found.
var rotateTokenScript = redis.NewScript(`
local oldData = redis.call('GET', KEYS[1])
if not oldData then
    return nil
end
redis.call('DEL', KEYS[1])
local sessionID = oldData:match('"session_id":"([^"]*)"')
if sessionID and sessionID ~= '' then
    local sessionKey = ARGV[3] .. sessionID
    redis.call('SREM', sessionKey, ARGV[1])
    redis.call('SADD', sessionKey, ARGV[2])
    redis.call('EXPIRE', sessionKey, ARGV[4])
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
// The old token is read and deleted in a single Lua script that also updates the
// session index, eliminating the separate pre-read round-trip. The new token is
// then stored based on the old token data returned by the script.
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

	// 3. Atomically read+delete old token and update session index in one Lua script.
	//    The script parses session_id from the old token JSON in-script, avoiding
	//    a separate pre-read GET round-trip.
	result, err := s.redis.RunScript(ctx, rotateTokenScript,
		[]string{oldKey},
		oldHash, newHash, sessionTokensKeyPrefix, expirySeconds,
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	// 4. Parse old token data returned by the script to build the new token.
	oldDataStr, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected type from rotate script: %T", result)
	}
	var oldRT domain.RefreshToken
	if err := json.Unmarshal([]byte(oldDataStr), &oldRT); err != nil {
		return nil, fmt.Errorf("unmarshal old refresh token: %w", err)
	}

	newRT, err := domain.NewRefreshToken(newTokenString, oldRT.AccountID, time.Now().Add(s.refreshExpiry))
	if err != nil {
		return nil, fmt.Errorf("create new refresh token: %w", err)
	}
	newRT.ClientID = oldRT.ClientID
	newRT.SessionID = oldRT.SessionID
	newRT.Scope = oldRT.Scope
	newRT.IP = oldRT.IP
	newRT.UserAgent = oldRT.UserAgent

	// 5. Store the new token in Redis.
	newData, err := json.Marshal(newRT)
	if err != nil {
		return nil, fmt.Errorf("marshal new refresh token: %w", err)
	}
	if err := s.redis.Set(ctx, newKey, newData, s.refreshExpiry); err != nil {
		return nil, fmt.Errorf("store new refresh token: %w", err)
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionTokenRotate,
		audit.IPFromContext(ctx),
		utility.Ptr[string](newRT.AccountID),
		utility.MarshalJSONOrEmpty(map[string]any{
			"session_id": newRT.SessionID,
			"old_token":  oldHash,
			"new_token":  newHash,
		}),
		utility.MarshalJSONOrEmpty(map[string]any{
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
			utility.MarshalJSONOrEmpty(map[string]any{
				"token_hash": domain.HashToken(token),
				"session_id": rt.SessionID,
			}),
			utility.MarshalJSONOrEmpty(map[string]any{
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
		utility.MarshalJSONOrEmpty(map[string]any{
			"session_id": sessionID,
			"reason":     "revoke_all_for_session",
		}),
		utility.MarshalJSONOrEmpty(map[string]any{
			"ip":         audit.IPFromContext(ctx),
			"user_agent": audit.UserAgentFromContext(ctx),
		}),
	))

	return nil
}

// RevokeAccessToken blacklists an access token by its JTI so it can no longer be used.
func (s *TokenService) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.blacklist.RevokeToken(ctx, jti, "logout", expiresAt)
}

// RevokeAccountTokens marks all access tokens for the given account as revoked.
// Tokens issued before this call will be rejected by ValidateAccessTokenWithContext.
// The revocation record automatically expires after accessExpiry duration.
func (s *TokenService) RevokeAccountTokens(ctx context.Context, accountID string) error {
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
		utility.Ptr[string](accountID),
		utility.MarshalJSONOrEmpty(map[string]any{
			"reason": "revoke_all_for_account",
		}),
		utility.MarshalJSONOrEmpty(map[string]any{
			"ip":         audit.IPFromContext(ctx),
			"user_agent": audit.UserAgentFromContext(ctx),
		}),
	))

	return nil
}
