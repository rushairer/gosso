package service

import (
	"github.com/redis/go-redis/v9"
)

// revokeAccountSessionsScript atomically reads all session IDs from the
// account_sessions set and deletes the set in a single EVAL call.
// This eliminates the TOCTOU window between SMembers and Del where new
// sessions can be created and then orphaned.
// KEYS[1] = account_sessions:{accountID}
// Returns: array of session ID strings (may be empty)
var revokeAccountSessionsScript = redis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
redis.call('DEL', KEYS[1])
return members
`)

// evictOldestSessionsScript atomically reads all sessions from the account
// index, identifies the oldest ones that exceed the max limit, deletes their
// keys, and removes them from the index — all in a single EVAL call.
// Corrupted sessions (unparseable JSON or missing last_active_at) are also
// cleaned up to prevent them from blocking new session creation.
// This eliminates the TOCTOU window in EnforceSessionLimit.
//
// KEYS[1] = account_sessions:{accountID}
// ARGV[1] = maxSessions (number of sessions to keep)
// Returns: array of evicted session ID strings (may be empty)
var evictOldestSessionsScript = redis.NewScript(`
local indexKey = KEYS[1]
local maxSessions = tonumber(ARGV[1])
local cjson = require('cjson')

local sessionIDs = redis.call('SMEMBERS', indexKey)
if #sessionIDs <= maxSessions then
    return {}
end

-- Read all session data to get last_active_at timestamps
local sessions = {}
local corrupted = {}
for i = 1, #sessionIDs do
    local data = redis.call('GET', 'session:' .. sessionIDs[i])
    if data then
        local ok, obj = pcall(cjson.decode, data)
        if ok and obj.last_active_at then
            table.insert(sessions, {id = sessionIDs[i], ts = obj.last_active_at})
        else
            -- Corrupted or missing last_active_at: clean up immediately
            table.insert(corrupted, sessionIDs[i])
        end
    else
        -- Key missing but still in index: clean up stale reference
        table.insert(corrupted, sessionIDs[i])
    end
end

-- Remove corrupted/stale sessions from index
for i = 1, #corrupted do
    redis.call('DEL', 'session:' .. corrupted[i])
    redis.call('SREM', indexKey, corrupted[i])
end

-- Sort by last_active_at (ascending = oldest first)
table.sort(sessions, function(a, b) return a.ts < b.ts end)

-- Evict the oldest sessions exceeding the limit
local toRemove = #sessions - maxSessions
local evicted = {}
for i = 1, toRemove do
    redis.call('DEL', 'session:' .. sessions[i].id)
    redis.call('SREM', indexKey, sessions[i].id)
    table.insert(evicted, sessions[i].id)
end
return evicted
`)

// createSessionScript atomically stores a session and adds it to the account
// session index in a single EVAL call. This eliminates the TOCTOU window
// between SET session and SADD index where a crash would create an orphaned session.
//
// KEYS[1] = session:{sessionID}
// KEYS[2] = account_sessions:{accountID}
// ARGV[1] = session data (JSON)
// ARGV[2] = session TTL in seconds
// ARGV[3] = session ID (for SADD member)
// Returns: OK
var createSessionScript = redis.NewScript(`
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
redis.call('EXPIRE', KEYS[2], ARGV[2])
return 'OK'
`)

// deleteIfExpiredScript atomically checks whether a session is truly expired
// and only deletes it if so. This prevents a concurrent RefreshSession (which
// extends the TTL via EXPIRE) from having its session incorrectly deleted by a
// stale ValidateSession that read the session before the refresh.
//
// KEYS[1] = session:{sessionID}
// Returns: 1 if deleted (expired) or already gone, 0 if kept (still valid)
var deleteIfExpiredScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return 1  -- already gone, treat as deleted
end

-- If PTTL > 0, someone recently refreshed the TTL (sliding window).
-- A truly expired session will have PTTL <= 0 (key expired or about to expire).
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then
    return 0  -- TTL is positive, session is alive — do not delete
end

redis.call('DEL', KEYS[1])
return 1
`)
