package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	consentKeyPrefix        = "consent:"
	consentTTL              = 90 * 24 * time.Hour        // 90 days
	consentCacheFallbackTTL = 5 * time.Minute            // short TTL when primary cache write fails
	consentTombstone        = `{"_tombstone":"revoked"}` // explicit marker for revoked consent cache entries
)

// ConsentService handles user consent for OAuth2 authorization.
// Uses the database as the source of truth with Redis as a write-through cache.
type ConsentService struct {
	db          *sql.DB
	consentRepo repository.ConsentRepository
	redis       *cache.RedisClient
	logger      *zap.Logger
}

// NewConsentService creates a new consent service instance.
func NewConsentService(db *sql.DB, consentRepo repository.ConsentRepository, redis *cache.RedisClient, logger *zap.Logger) (*ConsentService, error) {
	logger = utility.EnsureLogger(logger)
	if consentRepo == nil {
		return nil, fmt.Errorf("consent repository is required")
	}
	return &ConsentService{
		db:          db,
		consentRepo: consentRepo,
		redis:       redis,
		logger:      logger,
	}, nil
}

// GetConsent retrieves the user's consent record for a specific client.
// Checks Redis cache first, falls back to DB, and writes back to cache on miss.
func (s *ConsentService) GetConsent(ctx context.Context, accountID, clientID string) (*domain.Consent, error) {
	key := s.buildConsentKey(accountID, clientID)

	// Try Redis cache first
	data, err := s.redis.Get(ctx, key)
	if err == nil {
		// Check for explicit tombstone marker (consent was revoked but cache delete failed)
		if data == consentTombstone {
			// Tombstone hit — consent was revoked. Fall through to DB to confirm.
		} else {
			var consent domain.Consent
			jsonErr := json.Unmarshal([]byte(data), &consent)
			if jsonErr == nil {
				return &consent, nil
			}
			s.logger.Warn("consent cache corrupt, falling back to DB", zap.Error(jsonErr))
		}
	} else if !errors.Is(err, cache.ErrKeyNotFound) {
		s.logger.Warn("Redis consent cache read failed, falling back to DB",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
	}

	// Cache miss or error — read from DB
	consent, err := s.consentRepo.FindByAccountAndClient(ctx, accountID, clientID)
	if err != nil {
		if errors.Is(err, domain.ErrConsentNotFound) {
			return nil, domain.ErrConsentNotFound
		}
		return nil, fmt.Errorf("get consent from DB: %w", err)
	}

	// Write back to cache
	if cacheData, marshalErr := json.Marshal(consent); marshalErr == nil {
		if setErr := s.redis.Set(ctx, key, cacheData, consentTTL); setErr != nil {
			s.logger.Warn("Failed to write consent cache", zap.Error(setErr))
		}
	}

	return consent, nil
}

// SaveConsent saves the user's consent record to DB and updates the Redis cache.
func (s *ConsentService) SaveConsent(ctx context.Context, consent *domain.Consent) error {
	if consent == nil {
		return errors.New("consent must not be nil")
	}
	if consent.AccountID == "" || consent.ClientID == "" {
		return &ValidationError{Message: "consent account_id and client_id are required"}
	}

	consent.GrantedAt = time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.consentRepo.Upsert(ctx, tx, consent)
	})
	if err != nil {
		return fmt.Errorf("save consent to DB: %w", err)
	}

	// Write-through to Redis cache
	data, err := json.Marshal(consent)
	if err != nil {
		s.logger.Warn("Failed to marshal consent for cache", zap.Error(err))
	} else {
		key := s.buildConsentKey(consent.AccountID, consent.ClientID)
		if setErr := s.redis.Set(ctx, key, data, consentTTL); setErr != nil {
			s.logger.Warn("Failed to update consent cache, setting fallback TTL", zap.Error(setErr))
			// Use a short fallback TTL so stale data expires quickly instead of 90 days.
			_ = s.redis.Set(ctx, key, data, consentCacheFallbackTTL)
		}
	}

	s.logger.Info("Consent saved",
		zap.String("account_id", utility.MaskOpaqueID(consent.AccountID)),
		zap.String("client_id", consent.ClientID))

	return nil
}

// DeleteConsent deletes the user's consent record from both DB and Redis cache.
func (s *ConsentService) DeleteConsent(ctx context.Context, accountID, clientID string) error {
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.consentRepo.SoftDelete(ctx, tx, accountID, clientID, time.Now())
	})
	if err != nil {
		return fmt.Errorf("delete consent from DB: %w", err)
	}

	key := s.buildConsentKey(accountID, clientID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Warn("Failed to delete consent from Redis cache, setting fallback TTL", zap.Error(err))
		// If delete fails, the stale positive consent in cache could survive up to
		// 90 days. Overwrite with a tombstone that expires quickly, so the next
		// GetConsent falls through to the database.
		_ = s.redis.Set(ctx, key, consentTombstone, consentCacheFallbackTTL)
	}

	return nil
}

func (s *ConsentService) buildConsentKey(accountID, clientID string) string {
	return fmt.Sprintf("%s%s|%s", consentKeyPrefix, accountID, clientID)
}

// DeleteConsentsByAccount removes all consent cache entries for the given account.
// Uses SCAN to iterate matching keys and deletes them in batches.
// This is called when an account is deleted to prevent stale consent cache entries.
func (s *ConsentService) DeleteConsentsByAccount(ctx context.Context, accountID string) error {
	pattern := fmt.Sprintf("%s%s|*", consentKeyPrefix, accountID)
	var cursor uint64
	var totalDeleted int

	const maxIterations = 1000
	for i := 0; i < maxIterations; i++ {
		keys, nextCursor, err := s.redis.GetClient().Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("scan consent keys: %w", err)
		}
		if len(keys) > 0 {
			if err := s.redis.Del(ctx, keys...); err != nil {
				s.logger.Warn("Failed to delete consent cache keys", zap.Error(err), zap.Int("count", len(keys)))
			}
			totalDeleted += len(keys)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	if cursor != 0 {
		s.logger.Warn("DeleteConsentsByAccount SCAN exceeded max iterations",
			zap.String("account_id", utility.MaskOpaqueID(accountID)),
			zap.Int("max_iterations", maxIterations))
	}

	if totalDeleted > 0 {
		s.logger.Info("Cleared consent cache for account",
			zap.String("account_id", utility.MaskOpaqueID(accountID)),
			zap.Int("keys_deleted", totalDeleted))
	}
	return nil
}
