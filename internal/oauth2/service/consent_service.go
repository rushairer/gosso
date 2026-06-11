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
	ConsentKeyPrefix = "consent:"
	ConsentTTL       = 90 * 24 * time.Hour // 90 days
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
func NewConsentService(db *sql.DB, consentRepo repository.ConsentRepository, redis *cache.RedisClient, logger *zap.Logger) *ConsentService {
	logger = utility.EnsureLogger(logger)
	if consentRepo == nil {
		panic("consent repository is required")
	}
	return &ConsentService{
		db:          db,
		consentRepo: consentRepo,
		redis:       redis,
		logger:      logger,
	}
}

// GetConsent retrieves the user's consent record for a specific client.
// Checks Redis cache first, falls back to DB, and writes back to cache on miss.
func (s *ConsentService) GetConsent(ctx context.Context, accountID, clientID string) (*domain.Consent, error) {
	key := s.buildConsentKey(accountID, clientID)

	// Try Redis cache first
	data, err := s.redis.Get(ctx, key)
	if err == nil {
		var consent domain.Consent
		if jsonErr := json.Unmarshal([]byte(data), &consent); jsonErr == nil {
			return &consent, nil
		}
		// Cache corrupt — fall through to DB
	} else if err != cache.ErrKeyNotFound {
		s.logger.Warn("Redis consent cache read failed, falling back to DB",
			zap.String("account_id", accountID), zap.Error(err))
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
		if setErr := s.redis.Set(ctx, key, cacheData, ConsentTTL); setErr != nil {
			s.logger.Warn("Failed to write consent cache", zap.Error(setErr))
		}
	}

	return consent, nil
}

// SaveConsent saves the user's consent record to DB and updates the Redis cache.
func (s *ConsentService) SaveConsent(ctx context.Context, consent *domain.Consent) error {
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
		if setErr := s.redis.Set(ctx, key, data, ConsentTTL); setErr != nil {
			s.logger.Warn("Failed to update consent cache", zap.Error(setErr))
		}
	}

	s.logger.Info("Consent saved",
		zap.String("account_id", consent.AccountID),
		zap.String("client_id", consent.ClientID))

	return nil
}

// DeleteConsent deletes the user's consent record from both DB and Redis cache.
func (s *ConsentService) DeleteConsent(ctx context.Context, accountID, clientID string) error {
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.consentRepo.Delete(ctx, tx, accountID, clientID, time.Now())
	})
	if err != nil {
		return fmt.Errorf("delete consent from DB: %w", err)
	}

	key := s.buildConsentKey(accountID, clientID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Warn("Failed to delete consent from Redis cache", zap.Error(err))
	}

	return nil
}

func (s *ConsentService) buildConsentKey(accountID, clientID string) string {
	return fmt.Sprintf("%s%s|%s", ConsentKeyPrefix, accountID, clientID)
}
