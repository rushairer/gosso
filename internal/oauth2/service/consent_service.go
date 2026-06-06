package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/utility"
)

const (
	ConsentKeyPrefix = "consent:"
	ConsentTTL       = 90 * 24 * time.Hour // 90 days
)

// ConsentService handles user consent for OAuth2 authorization (stored in Redis)
type ConsentService struct {
	redis  *cache.RedisClient
	logger *zap.Logger
}

// NewConsentService creates a new consent service instance
func NewConsentService(redis *cache.RedisClient, logger *zap.Logger) *ConsentService {
	logger = utility.EnsureLogger(logger)
	return &ConsentService{
		redis:  redis,
		logger: logger,
	}
}

// GetConsent retrieves the user's consent record for a specific client
func (s *ConsentService) GetConsent(ctx context.Context, accountID, clientID string) (*domain.Consent, error) {
	key := s.buildConsentKey(accountID, clientID)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, nil // Not authorized before, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("get consent: %w", err)
	}

	var consent domain.Consent
	if err := json.Unmarshal([]byte(data), &consent); err != nil {
		return nil, fmt.Errorf("unmarshal consent: %w", err)
	}

	return &consent, nil
}

// SaveConsent saves the user's consent record
func (s *ConsentService) SaveConsent(ctx context.Context, consent *domain.Consent) error {
	consent.GrantedAt = time.Now()

	data, err := json.Marshal(consent)
	if err != nil {
		return fmt.Errorf("marshal consent: %w", err)
	}

	key := s.buildConsentKey(consent.AccountID, consent.ClientID)
	if err := s.redis.Set(ctx, key, data, ConsentTTL); err != nil {
		return fmt.Errorf("save consent: %w", err)
	}

	s.logger.Info("Consent saved",
		zap.String("account_id", consent.AccountID),
		zap.String("client_id", consent.ClientID))

	return nil
}

// DeleteConsent deletes the user's consent record
func (s *ConsentService) DeleteConsent(ctx context.Context, accountID, clientID string) error {
	key := s.buildConsentKey(accountID, clientID)
	if err := s.redis.Del(ctx, key); err != nil {
		return fmt.Errorf("delete consent: %w", err)
	}
	return nil
}

func (s *ConsentService) buildConsentKey(accountID, clientID string) string {
	return fmt.Sprintf("%s%s:%s", ConsentKeyPrefix, accountID, clientID)
}
