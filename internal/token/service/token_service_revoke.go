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

const (
	refreshTokenConsumedKeyPrefix = "refresh_token_consumed:"
	refreshTokenConsumedTTL       = 7 * 24 * time.Hour
)

// rotateAndDeleteAndCleanSessionScript atomically retrieves and deletes a refresh token,
// then removes the token hash from the session index — all in a single Redis round-trip.
// This prevents TOCTOU race conditions during refresh token rotation.
// Uses string pattern matching instead of cjson so it works across Redis Lua
// sandboxes and miniredis-backed tests.
// KEYS[1] = refresh token key
// ARGV[1] = session tokens key prefix (session_tokens:)
// ARGV[2] = token hash
// Returns the token data if it existed (and was deleted), or nil if it was already consumed.
var rotateAndDeleteScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if data then
    redis.call('DEL', KEYS[1])
    local sessionID = data:match('"session_id":"([^"]*)"')
    if sessionID and sessionID ~= '' then
        redis.call('SREM', ARGV[1] .. sessionID, ARGV[2])
    end
end
return data
`)

// rotateTokenScript atomically reads and deletes the old refresh token, stores
// the new refresh token, updates the session index (SREM old hash, SADD new hash),
// and marks the old token as consumed to detect replay attacks.
// If the old token was already consumed, it revokes all tokens for the session (token family revocation)
// and returns "REUSE_DETECTED".
// KEYS[1] = old token key
// KEYS[2] = new token key
// KEYS[3] = consumed key for old token hash
// ARGV[1] = old token hash, ARGV[2] = new token hash, ARGV[3] = session key prefix,
// ARGV[4] = refresh token expiry seconds, ARGV[5] = new token data,
// ARGV[6] = consumed TTL seconds, ARGV[7] = refresh token key prefix
// Returns "OK" on success, "REUSE_DETECTED" on reuse, nil if old token not found.
var rotateTokenScript = redis.NewScript(`
local oldData = redis.call('GET', KEYS[1])
if not oldData then
    local consumed = redis.call('GET', KEYS[3])
    if consumed then
        local sessionID = consumed:match('"session_id":"([^"]*)"')
        if sessionID and sessionID ~= '' then
            local sessionKey = ARGV[3] .. sessionID
            local members = redis.call('SMEMBERS', sessionKey)
            for _, hash in ipairs(members) do
                redis.call('DEL', ARGV[7] .. hash)
            end
            redis.call('DEL', sessionKey)
        end
        return "REUSE_DETECTED"
    end
    return nil
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[5], 'EX', ARGV[4])
redis.call('SET', KEYS[3], oldData, 'EX', ARGV[6])
local sessionID = oldData:match('"session_id":"([^"]*)"')
if sessionID and sessionID ~= '' then
    local sessionKey = ARGV[3] .. sessionID
    redis.call('SREM', sessionKey, ARGV[1])
    redis.call('SADD', sessionKey, ARGV[2])
    redis.call('EXPIRE', sessionKey, ARGV[4])
end
return "OK"
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
// It consumes the old token, stores the new token, updates the session-token
// index, and marks the consumed token. If a consumed token is presented again,
// it triggers reuse detection by revoking the entire session and returning an error.
func (s *TokenService) RotateRefreshToken(ctx context.Context, oldToken string) (*domain.RefreshToken, error) {
	// 1. Generate new token
	newBytes := make([]byte, refreshTokenLength)
	if _, err := rand.Read(newBytes); err != nil {
		return nil, fmt.Errorf("generate new token: %w", err)
	}
	newTokenString := hex.EncodeToString(newBytes)

	// 2. Load the old token metadata used to construct the replacement.
	oldKey := s.buildRefreshTokenKey(oldToken)
	oldHash := domain.HashToken(oldToken)
	consumedKey := s.buildRefreshTokenConsumedKey(oldHash)

	oldData, err := s.redis.Get(ctx, oldKey)
	if errors.Is(err, cache.ErrKeyNotFound) {
		consumedData, cErr := s.redis.Get(ctx, consumedKey)
		if cErr == nil && consumedData != "" {
			var oldRT domain.RefreshToken
			if unmarshalErr := json.Unmarshal([]byte(consumedData), &oldRT); unmarshalErr == nil && oldRT.SessionID != "" {
				_ = s.RevokeAllForSession(ctx, oldRT.SessionID)
			}
			s.logger.Warn("Refresh token reuse detected, revoked all session tokens",
				zap.String("token_hash", oldHash))
			auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
				auditDomain.ActionTokenRevoke,
				audit.IPFromContext(ctx),
				nil,
				utility.MarshalJSONOrEmpty(map[string]any{
					"reason":     "refresh_token_reuse_detected",
					"token_hash": oldHash,
				}),
				utility.MarshalJSONOrEmpty(map[string]any{
					"ip":         audit.IPFromContext(ctx),
					"user_agent": audit.UserAgentFromContext(ctx),
				}),
			))
			return nil, fmt.Errorf("refresh token reuse detected: %w", cache.ErrKeyNotFound)
		}
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token for rotation: %w", err)
	}

	var oldRT domain.RefreshToken
	if unmarshalErr := json.Unmarshal([]byte(oldData), &oldRT); unmarshalErr != nil {
		return nil, fmt.Errorf("unmarshal old refresh token: %w", unmarshalErr)
	}

	newRT, err := domain.NewRefreshToken(newTokenString, oldRT.AccountID, time.Now().Add(s.refreshExpiry))
	if err != nil {
		return nil, fmt.Errorf("create new refresh token: %w", err)
	}
	newRT.ClientID = oldRT.ClientID
	newRT.SessionID = oldRT.SessionID
	newRT.Scope = oldRT.Scope
	newRT.Resource = oldRT.Resource
	newRT.IP = oldRT.IP
	newRT.UserAgent = oldRT.UserAgent

	// 3. Atomically consume old token, store new token, and mark old token as consumed.
	newHash := domain.HashToken(newTokenString)
	newKey := s.buildRefreshTokenKey(newTokenString)
	expirySeconds := int(math.Ceil(s.refreshExpiry.Seconds()))
	consumedTTLSeconds := int(math.Ceil(refreshTokenConsumedTTL.Seconds()))

	newData, err := json.Marshal(newRT)
	if err != nil {
		return nil, fmt.Errorf("marshal new refresh token: %w", err)
	}

	result, err := s.redis.RunScript(ctx, rotateTokenScript,
		[]string{oldKey, newKey, consumedKey},
		oldHash, newHash, sessionTokensKeyPrefix, expirySeconds, string(newData), consumedTTLSeconds, refreshTokenKeyPrefix,
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	resultStr, ok := result.(string)
	if ok && resultStr == "REUSE_DETECTED" {
		s.logger.Warn("Refresh token reuse detected in rotation script, session tokens revoked",
			zap.String("token_hash", oldHash))
		return nil, fmt.Errorf("refresh token reuse detected: %w", cache.ErrKeyNotFound)
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

func (s *TokenService) buildRefreshTokenConsumedKey(oldHash string) string {
	return refreshTokenConsumedKeyPrefix + oldHash
}

// RevokeRefreshToken revokes a refresh token and removes it from the session index.
func (s *TokenService) RevokeRefreshToken(ctx context.Context, token string) error {
	key := s.buildRefreshTokenKey(token)
	tokenHash := domain.HashToken(token)

	data, err := s.redis.RunScript(ctx, rotateAndDeleteScript, []string{key},
		sessionTokensKeyPrefix, tokenHash,
	).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	if dataStr, ok := data.(string); ok && dataStr != "" {
		var rt domain.RefreshToken
		if jsonErr := json.Unmarshal([]byte(dataStr), &rt); jsonErr == nil {
			auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
				auditDomain.ActionTokenRevoke,
				audit.IPFromContext(ctx),
				nil,
				utility.MarshalJSONOrEmpty(map[string]any{
					"token_hash": tokenHash,
					"session_id": rt.SessionID,
				}),
				utility.MarshalJSONOrEmpty(map[string]any{
					"ip":         audit.IPFromContext(ctx),
					"user_agent": audit.UserAgentFromContext(ctx),
				}),
			))
		}
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
