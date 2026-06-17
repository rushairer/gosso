package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
	UpdateClientByAccountID(ctx context.Context, accountID, clientID string, req *UpdateClientRequest) (*domain.OAuth2Client, error)
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

	// Validate client metadata before persisting
	if strings.TrimSpace(req.Name) == "" {
		return nil, "", &ValidationError{Message: "client name is required"}
	}
	if len(req.Name) > 256 {
		return nil, "", &ValidationError{Message: "client name must not exceed 256 characters"}
	}
	if len(req.Description) > 1024 {
		return nil, "", &ValidationError{Message: "client description must not exceed 1024 characters"}
	}
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return nil, "", err
	}
	if err := validateRedirectURIs(req.PostLogoutRedirectURIs); err != nil {
		return nil, "", fmt.Errorf("post_logout_redirect_uris: %w", err)
	}
	if len(req.GrantTypes) > 0 {
		if err := validateGrantTypes(req.GrantTypes); err != nil {
			return nil, "", err
		}
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

	client, err := domain.NewOAuth2Client(req.AccountID, req.Name, clientID, grantTypes)
	if err != nil {
		return nil, "", fmt.Errorf("create oauth2 client: %w", err)
	}
	client.ClientSecretHash = secretHash
	client.Description = req.Description
	client.RedirectURIs = req.RedirectURIs
	client.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	client.Scopes = scopes
	client.IsConfidential = req.IsConfidential
	client.Metadata = req.Metadata

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.clientRepo.Create(ctx, tx, client)
	})
	if err != nil {
		return nil, "", fmt.Errorf("register client: %w", err)
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

// UpdateClientRequest contains the fields that can be updated on an OAuth2 client.
type UpdateClientRequest struct {
	Name                   *string  `json:"name"`
	Description            *string  `json:"description"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	GrantTypes             []string `json:"grant_types"`
	Scopes                 []string `json:"scopes"`
}

// UpdateClientByAccountID loads a client by ID, verifies ownership, applies partial updates with
// validation, and persists the result in a single transaction.
func (s *oauth2ClientServiceImpl) UpdateClientByAccountID(ctx context.Context, accountID, clientID string, req *UpdateClientRequest) (*domain.OAuth2Client, error) {
	client, err := s.clientRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrClientNotFound, clientID)
	}
	if client.AccountID != accountID {
		return nil, ErrClientAccessDenied
	}

	if req.Name != nil {
		if len(*req.Name) > 256 {
			return nil, &ValidationError{Message: "name must not exceed 256 characters"}
		}
		client.Name = *req.Name
	}
	if req.Description != nil {
		if len(*req.Description) > 1024 {
			return nil, &ValidationError{Message: "description must not exceed 1024 characters"}
		}
		client.Description = *req.Description
	}
	if req.RedirectURIs != nil {
		if len(req.RedirectURIs) == 0 {
			return nil, &ValidationError{Message: "redirect_uris must not be empty when provided"}
		}
		if err := validateRedirectURIs(req.RedirectURIs); err != nil {
			return nil, err
		}
		client.RedirectURIs = req.RedirectURIs
	}
	if req.PostLogoutRedirectURIs != nil {
		if err := validateRedirectURIs(req.PostLogoutRedirectURIs); err != nil {
			return nil, fmt.Errorf("post_logout_redirect_uris: %w", err)
		}
		client.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	}
	if req.GrantTypes != nil {
		if err := validateGrantTypes(req.GrantTypes); err != nil {
			return nil, err
		}
		client.GrantTypes = req.GrantTypes
	}
	if req.Scopes != nil {
		client.Scopes = req.Scopes
	}
	client.UpdatedAt = time.Now()

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.clientRepo.Update(ctx, tx, client)
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}

var validGrantTypes = []string{
	domain.GrantTypeAuthorizationCode,
	domain.GrantTypeRefreshToken,
	domain.GrantTypeClientCredentials,
	domain.GrantTypeDeviceCode,
}

func validateGrantTypes(types []string) error {
	for _, gt := range types {
		found := false
		for _, valid := range validGrantTypes {
			if gt == valid {
				found = true
				break
			}
		}
		if !found {
			return &ValidationError{Message: fmt.Sprintf("invalid grant_type: %q", gt)}
		}
	}
	return nil
}

func validateRedirectURIs(uris []string) error {
	for _, uri := range uris {
		u, err := url.Parse(uri)
		if err != nil || u.Fragment != "" || u.Host == "" {
			return &ValidationError{Message: fmt.Sprintf("redirect_uris must use a valid host without fragment: %s", uri)}
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return &ValidationError{Message: fmt.Sprintf("redirect_uris must use http or https scheme: %s", uri)}
		}
		// Per RFC 6749 Section 3.1.2 and OAuth 2.0 Security Best Current Practice (RFC 9700),
		// HTTP is only allowed for loopback addresses (native app development).
		if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			return &ValidationError{Message: fmt.Sprintf("redirect_uris must use https for non-loopback hosts: %s", uri)}
		}
	}
	return nil
}

// isLoopbackHost checks if a hostname is a loopback address.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
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
