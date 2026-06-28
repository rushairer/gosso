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
	refreshTokenReplayKeyPrefix = "refresh_token_replay:"
	refreshTokenReplayTTL       = 30 * time.Second
)

type refreshTokenReplay struct {
	Token     string    `json:"token"`
	AccountID string    `json:"account_id"`
	ClientID  string    `json:"client_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// rotateAndDeleteAndCleanSessionScript atomically retrieves and deletes a refresh token,
// then removes the token hash from the session index — all in a single Redis round-trip.
// This prevents TOCTOU race conditions during refresh token rotation.
// Uses cjson.decode for robust JSON parsing when available (real Redis), falling back
// to string pattern matching for environments without cjson (e.g., miniredis in tests).
// KEYS[1] = refresh token key
// ARGV[1] = session tokens key prefix (session_tokens:)
// ARGV[2] = token hash
// Returns the token data if it existed (and was deleted), or nil if it was already consumed.
var rotateAndDeleteScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if data then
    redis.call('DEL', KEYS[1])
    local sessionID
    local cjson_ok, cjson = pcall(require, 'cjson')
    if cjson_ok then
        local ok, obj = pcall(cjson.decode, data)
        if ok and obj then
            sessionID = obj.session_id
        end
    else
        sessionID = data:match('"session_id":"([^"]*)"')
    end
    if sessionID and sessionID ~= '' then
        redis.call('SREM', ARGV[1] .. sessionID, ARGV[2])
    end
end
return data
`)

// rotateTokenScript atomically reads and deletes the old refresh token, stores
// the new refresh token, records a short replay result, and updates the session
// index (SREM old hash, SADD new hash) in a single Lua script.
// The session ID is parsed from the old token JSON inside the script, eliminating
// the need for a separate pre-read round-trip in Go.
// Uses cjson.decode for robust JSON parsing when available (real Redis), falling back
// to string pattern matching for environments without cjson (e.g., miniredis in tests).
// KEYS[1] = old token key
// KEYS[2] = new token key
// KEYS[3] = replay key for old token hash
// ARGV[1] = old token hash, ARGV[2] = new token hash, ARGV[3] = session key prefix,
// ARGV[4] = refresh token expiry seconds, ARGV[5] = new token data,
// ARGV[6] = replay data, ARGV[7] = replay TTL seconds
// Returns replay data on fresh rotation or replay hit, nil if old token not found.
var rotateTokenScript = redis.NewScript(`
local oldData = redis.call('GET', KEYS[1])
if not oldData then
    return redis.call('GET', KEYS[3])
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[5], 'EX', ARGV[4])
redis.call('SET', KEYS[3], ARGV[6], 'EX', ARGV[7])
local sessionID
local cjson_ok, cjson = pcall(require, 'cjson')
if cjson_ok then
    local ok, obj = pcall(cjson.decode, oldData)
    if ok and obj then
        sessionID = obj.session_id
    end
else
    sessionID = oldData:match('"session_id":"([^"]*)"')
end
if sessionID and sessionID ~= '' then
    local sessionKey = ARGV[3] .. sessionID
    redis.call('SREM', sessionKey, ARGV[1])
    redis.call('SADD', sessionKey, ARGV[2])
    redis.call('EXPIRE', sessionKey, ARGV[4])
end
return ARGV[6]
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
// index, and writes a short replay record in one Redis script. The replay record
// lets concurrent browser retries using the just-consumed token receive the same
// rotated token instead of failing the whole session.
func (s *TokenService) RotateRefreshToken(ctx context.Context, oldToken string) (*domain.RefreshToken, error) {
	// 1. Generate new token
	newBytes := make([]byte, refreshTokenLength)
	if _, err := rand.Read(newBytes); err != nil {
		return nil, fmt.Errorf("generate new token: %w", err)
	}
	newTokenString := hex.EncodeToString(newBytes)

	// 2. Load the old token metadata used to construct the replacement. If the
	// old token was just consumed by a concurrent refresh, return the replayed
	// rotated token when it is still inside the short grace window.
	oldKey := s.buildRefreshTokenKey(oldToken)
	oldHash := domain.HashToken(oldToken)
	replayKey := s.buildRefreshTokenReplayKey(oldHash)
	oldData, err := s.redis.Get(ctx, oldKey)
	if errors.Is(err, cache.ErrKeyNotFound) {
		replay, replayErr := s.getRefreshTokenReplay(ctx, replayKey)
		if replayErr == nil {
			return replay, nil
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
	newRT.IP = oldRT.IP
	newRT.UserAgent = oldRT.UserAgent

	// 3. Atomically consume old token, store new token, update indexes, and
	// publish a short replay result for concurrent retries.
	newHash := domain.HashToken(newTokenString)
	newKey := s.buildRefreshTokenKey(newTokenString)
	expirySeconds := int(math.Ceil(s.refreshExpiry.Seconds()))
	replaySeconds := int(math.Ceil(refreshTokenReplayTTL.Seconds()))

	newData, err := json.Marshal(newRT)
	if err != nil {
		return nil, fmt.Errorf("marshal new refresh token: %w", err)
	}
	replayData, err := json.Marshal(refreshTokenReplay{
		Token:     newRT.Token,
		AccountID: newRT.AccountID,
		ClientID:  newRT.ClientID,
		SessionID: newRT.SessionID,
		Scope:     newRT.Scope,
		IP:        newRT.IP,
		UserAgent: newRT.UserAgent,
		ExpiresAt: newRT.ExpiresAt,
		CreatedAt: newRT.CreatedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal refresh token replay: %w", err)
	}

	result, err := s.redis.RunScript(ctx, rotateTokenScript,
		[]string{oldKey, newKey, replayKey},
		oldHash, newHash, sessionTokensKeyPrefix, expirySeconds, string(newData), string(replayData), replaySeconds,
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		replay, replayErr := s.getRefreshTokenReplay(ctx, replayKey)
		if replayErr == nil {
			return replay, nil
		}
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	resultData, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected type from rotate script: %T", result)
	}
	rotatedRT, err := parseRefreshTokenReplay(resultData)
	if err != nil {
		return nil, err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionTokenRotate,
		audit.IPFromContext(ctx),
		utility.Ptr[string](rotatedRT.AccountID),
		utility.MarshalJSONOrEmpty(map[string]any{
			"session_id": rotatedRT.SessionID,
			"old_token":  oldHash,
			"new_token":  domain.HashToken(rotatedRT.Token),
		}),
		utility.MarshalJSONOrEmpty(map[string]any{
			"ip":         audit.IPFromContext(ctx),
			"user_agent": audit.UserAgentFromContext(ctx),
		}),
	))

	return rotatedRT, nil
}

func (s *TokenService) buildRefreshTokenReplayKey(oldHash string) string {
	return refreshTokenReplayKeyPrefix + oldHash
}

func (s *TokenService) getRefreshTokenReplay(ctx context.Context, replayKey string) (*domain.RefreshToken, error) {
	data, err := s.redis.Get(ctx, replayKey)
	if err != nil {
		return nil, err
	}
	replay, err := parseRefreshTokenReplay(data)
	if err != nil {
		return nil, err
	}
	if _, err := s.ValidateRefreshToken(ctx, replay.Token); err != nil {
		return nil, err
	}
	return replay, nil
}

func parseRefreshTokenReplay(data string) (*domain.RefreshToken, error) {
	var replay refreshTokenReplay
	if err := json.Unmarshal([]byte(data), &replay); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token replay: %w", err)
	}
	if replay.Token == "" || replay.AccountID == "" || replay.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("invalid refresh token replay")
	}
	return &domain.RefreshToken{
		Token:     replay.Token,
		AccountID: replay.AccountID,
		ClientID:  replay.ClientID,
		SessionID: replay.SessionID,
		Scope:     replay.Scope,
		IP:        replay.IP,
		UserAgent: replay.UserAgent,
		ExpiresAt: replay.ExpiresAt,
		CreatedAt: replay.CreatedAt,
	}, nil
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
