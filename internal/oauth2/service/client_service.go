package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/oauth2/repository"
)

// RegisterClientRequest represents a request to register an OAuth2 client
type RegisterClientRequest struct {
	AccountID              string
	Name                   string
	Description            string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	Scopes                 []string
	IsConfidential         bool
	Metadata               map[string]any
}

// OAuth2ClientService is the OAuth2 client service interface
type OAuth2ClientService interface {
	RegisterClient(ctx context.Context, req *RegisterClientRequest) (*domain.OAuth2Client, string, error)
	FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error)
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
	UpdateClient(ctx context.Context, client *domain.OAuth2Client) error
	DeleteClient(ctx context.Context, accountID, clientID string) error
}

type oauth2ClientServiceImpl struct {
	db         *sql.DB
	clientRepo repository.OAuth2ClientRepository
}

// NewOAuth2ClientService creates a new OAuth2 client service instance
func NewOAuth2ClientService(db *sql.DB, clientRepo repository.OAuth2ClientRepository) OAuth2ClientService {
	return &oauth2ClientServiceImpl{
		db:         db,
		clientRepo: clientRepo,
	}
}

func (s *oauth2ClientServiceImpl) RegisterClient(ctx context.Context, req *RegisterClientRequest) (*domain.OAuth2Client, string, error) {
	clientID, err := generateClientID()
	if err != nil {
		return nil, "", fmt.Errorf("generate client id: %w", err)
	}
	var secretPlaintext string
	var secretHash string

	if req.IsConfidential {
		secretPlaintext, err = generateClientSecret()
		if err != nil {
			return nil, "", fmt.Errorf("generate client secret: %w", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(secretPlaintext), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("hash client secret: %w", err)
		}
		secretHash = string(hash)
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{domain.GrantTypeAuthorizationCode}
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	client := &domain.OAuth2Client{
		AccountID:              req.AccountID,
		ClientID:               clientID,
		ClientSecretHash:       secretHash,
		Name:                   req.Name,
		Description:            req.Description,
		RedirectURIs:           req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs,
		GrantTypes:             grantTypes,
		Scopes:                 scopes,
		IsConfidential:         req.IsConfidential,
		Metadata:               req.Metadata,
	}

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.clientRepo.Create(ctx, tx, client)
	})
	if err != nil {
		return nil, "", err
	}

	return client, secretPlaintext, nil
}

func (s *oauth2ClientServiceImpl) FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	return s.clientRepo.FindByClientID(ctx, clientID)
}

func (s *oauth2ClientServiceImpl) FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error) {
	return s.clientRepo.FindByAccountID(ctx, accountID)
}

func (s *oauth2ClientServiceImpl) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.clientRepo.Update(ctx, tx, client)
	})
}

var ErrClientAccessDenied = errors.New("access denied: client does not belong to this account")

func (s *oauth2ClientServiceImpl) DeleteClient(ctx context.Context, accountID, clientID string) error {
	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		client, err := s.clientRepo.FindByClientIDTx(ctx, tx, clientID)
		if err != nil {
			return err
		}
		if client.AccountID != accountID {
			return ErrClientAccessDenied
		}
		return s.clientRepo.SoftDelete(ctx, tx, client.ID, time.Now())
	})
}

// generateClientID generates a 24-byte client_id (48 hex characters)
func generateClientID() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// generateClientSecret generates a 32-byte client_secret (64 hex characters)
func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
