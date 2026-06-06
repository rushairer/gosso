package repository

import (
	"context"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

// ConsentRepository is the OAuth2 consent repository interface.
type ConsentRepository interface {
	Upsert(ctx context.Context, consent *domain.Consent) error
	FindByAccountAndClient(ctx context.Context, accountID, clientID string) (*domain.Consent, error)
	Delete(ctx context.Context, accountID, clientID string) error
}
