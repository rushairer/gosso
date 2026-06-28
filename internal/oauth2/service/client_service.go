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

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/utility"
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
	AllowReservedScopes    bool
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
	auditor    *auditService.Auditor
	logger     *zap.Logger
}

// NewOAuth2ClientService creates a new OAuth2 client service instance
func NewOAuth2ClientService(db *sql.DB, clientRepo repository.OAuth2ClientRepository, auditor *auditService.Auditor, logger *zap.Logger) OAuth2ClientService {
	return &oauth2ClientServiceImpl{
		db:         db,
		clientRepo: clientRepo,
		auditor:    auditor,
		logger:     utility.EnsureLogger(logger),
	}
}

func (s *oauth2ClientServiceImpl) RegisterClient(ctx context.Context, req *RegisterClientRequest) (*domain.OAuth2Client, string, error) {
	clientID, err := generateClientID()
	if err != nil {
		return nil, "", fmt.Errorf("generate client id: %w", err)
	}

	// Validate client metadata before persisting
	if validationErr := validateClientName(req.Name, true); validationErr != nil {
		return nil, "", validationErr
	}
	if validationErr := validateClientDescription(req.Description); validationErr != nil {
		return nil, "", validationErr
	}
	if validationErr := validateRedirectURIs(req.RedirectURIs); validationErr != nil {
		return nil, "", validationErr
	}
	if validationErr := validateRedirectURIs(req.PostLogoutRedirectURIs); validationErr != nil {
		return nil, "", fmt.Errorf("post_logout_redirect_uris: %w", validationErr)
	}
	if len(req.GrantTypes) > 0 {
		if validationErr := validateGrantTypes(req.GrantTypes); validationErr != nil {
			return nil, "", validationErr
		}
	}

	var secretPlaintext string
	var secretHash string

	if req.IsConfidential {
		secretPlaintext, err = generateClientSecret()
		if err != nil {
			return nil, "", fmt.Errorf("generate client secret: %w", err)
		}
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(secretPlaintext), bcrypt.DefaultCost)
		if hashErr != nil {
			return nil, "", fmt.Errorf("hash client secret: %w", hashErr)
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
	if validationErr := validateScopes(scopes); validationErr != nil {
		return nil, "", validationErr
	}
	if !req.AllowReservedScopes {
		if validationErr := validateUserManagedScopes(scopes); validationErr != nil {
			return nil, "", validationErr
		}
	}
	metadata := syncAdminCapability(req.Metadata, scopes)
	if len(metadata) == 0 {
		metadata = nil
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
	client.Metadata = metadata

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.clientRepo.Create(ctx, tx, client)
	})
	if err != nil {
		return nil, "", fmt.Errorf("register client: %w", err)
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionOAuth2ClientRegister,
		audit.IPFromContext(ctx),
		&req.AccountID,
		utility.MarshalJSONOrEmpty(map[string]any{"client_id": client.ClientID, "name": client.Name}),
		nil,
	))

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
		current, err := s.clientRepo.FindByClientIDTx(ctx, tx, client.ClientID)
		if err != nil {
			return err
		}
		expectedUpdatedAt := current.UpdatedAt
		client.UpdatedAt = time.Now()
		return s.clientRepo.Update(ctx, tx, client, expectedUpdatedAt)
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
	AllowReservedScopes    bool     `json:"-"`
}

// UpdateClientByAccountID loads a client by ID, verifies ownership, applies partial updates with
// validation, and persists the result in a single transaction with optimistic locking.
func (s *oauth2ClientServiceImpl) UpdateClientByAccountID(ctx context.Context, accountID, clientID string, req *UpdateClientRequest) (*domain.OAuth2Client, error) {
	// Validate request fields before starting the transaction
	if req.Name != nil {
		if err := validateClientName(*req.Name, false); err != nil {
			return nil, err
		}
	}
	if req.Description != nil {
		if err := validateClientDescription(*req.Description); err != nil {
			return nil, err
		}
	}
	if req.RedirectURIs != nil {
		if len(req.RedirectURIs) == 0 {
			return nil, &ValidationError{Message: "redirect_uris must not be empty when provided"}
		}
		if err := validateRedirectURIs(req.RedirectURIs); err != nil {
			return nil, err
		}
	}
	if req.PostLogoutRedirectURIs != nil {
		if err := validateRedirectURIs(req.PostLogoutRedirectURIs); err != nil {
			return nil, fmt.Errorf("post_logout_redirect_uris: %w", err)
		}
	}
	if req.GrantTypes != nil {
		if err := validateGrantTypes(req.GrantTypes); err != nil {
			return nil, err
		}
	}

	var client *domain.OAuth2Client
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Read inside the transaction for a consistent snapshot
		c, err := s.clientRepo.FindByClientIDTx(ctx, tx, clientID)
		if err != nil {
			return fmt.Errorf("%w: %s", domain.ErrClientNotFound, clientID)
		}
		if c.AccountID != accountID {
			return ErrClientAccessDenied
		}

		// Apply partial updates
		if req.Name != nil {
			c.Name = *req.Name
		}
		if req.Description != nil {
			c.Description = *req.Description
		}
		if req.RedirectURIs != nil {
			c.RedirectURIs = req.RedirectURIs
		}
		if req.PostLogoutRedirectURIs != nil {
			c.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
		}
		if req.GrantTypes != nil {
			c.GrantTypes = req.GrantTypes
		}
		if req.Scopes != nil {
			if err := validateScopes(req.Scopes); err != nil {
				return err
			}
			if !req.AllowReservedScopes {
				if err := validateUserManagedScopes(req.Scopes); err != nil {
					return err
				}
			}
			c.Scopes = req.Scopes
			c.Metadata = syncAdminCapability(c.Metadata, c.Scopes)
		}

		expectedUpdatedAt := c.UpdatedAt
		c.UpdatedAt = time.Now()
		if err := s.clientRepo.Update(ctx, tx, c, expectedUpdatedAt); err != nil {
			return err
		}
		client = c
		return nil
	})
	if err != nil {
		return nil, err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionOAuth2ClientUpdate,
		audit.IPFromContext(ctx),
		&accountID,
		utility.MarshalJSONOrEmpty(map[string]any{"client_id": client.ClientID, "name": client.Name}),
		nil,
	))

	return client, nil
}

var validGrantTypes = []string{
	domain.GrantTypeAuthorizationCode,
	domain.GrantTypeRefreshToken,
	domain.GrantTypeClientCredentials,
	domain.GrantTypeDeviceCode,
}

// validateClientName validates a client name. If required is true, empty names are rejected.
// Whitespace-only names are always rejected.
func validateClientName(name string, required bool) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		if required {
			return &ValidationError{Message: "client name is required"}
		}
		if name != "" {
			return &ValidationError{Message: "client name must not be only whitespace"}
		}
		return nil
	}
	if len(trimmed) > 256 {
		return &ValidationError{Message: "client name must not exceed 256 characters"}
	}
	return nil
}

// validateClientDescription validates a client description length.
func validateClientDescription(desc string) error {
	if len(desc) > 1024 {
		return &ValidationError{Message: "client description must not exceed 1024 characters"}
	}
	return nil
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

const (
	maxScopes      = 30
	maxScopeLength = 256
)

// validateScopes validates that scope values are well-formed.
func validateScopes(scopes []string) error {
	if len(scopes) > maxScopes {
		return &ValidationError{Message: fmt.Sprintf("too many scopes (max %d)", maxScopes)}
	}
	for _, s := range scopes {
		if strings.TrimSpace(s) == "" {
			return &ValidationError{Message: "scope must not be empty"}
		}
		if len(s) > maxScopeLength {
			return &ValidationError{Message: fmt.Sprintf("scope %q exceeds maximum length of %d characters", s, maxScopeLength)}
		}
	}
	return nil
}

func validateUserManagedScopes(scopes []string) error {
	for _, s := range scopes {
		if domain.IsAdminScope(s) {
			return &ValidationError{Message: fmt.Sprintf("scope %q is reserved for administrator clients", s)}
		}
	}
	return nil
}

func syncAdminCapability(metadata map[string]any, scopes []string) map[string]any {
	hasAdminScope := false
	for _, scope := range scopes {
		if domain.IsAdminScope(scope) {
			hasAdminScope = true
			break
		}
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	if hasAdminScope {
		metadata[domain.ClientCapabilityMetadataKey] = domain.ClientCapabilityAdmin
	} else {
		delete(metadata, domain.ClientCapabilityMetadataKey)
	}
	return metadata
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
		if u.Scheme == "http" && !domain.IsLoopback(u.Hostname()) {
			return &ValidationError{Message: fmt.Sprintf("redirect_uris must use https for non-loopback hosts: %s", uri)}
		}
	}
	return nil
}

var ErrClientAccessDenied = errors.New("access denied: client does not belong to this account")

func (s *oauth2ClientServiceImpl) DeleteClient(ctx context.Context, accountID, clientID string) error {
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		client, err := s.clientRepo.FindByClientIDTx(ctx, tx, clientID)
		if err != nil {
			return err
		}
		if client.AccountID != accountID {
			return ErrClientAccessDenied
		}
		return s.clientRepo.SoftDelete(ctx, tx, client.ID, time.Now())
	})
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionOAuth2ClientDelete,
		audit.IPFromContext(ctx),
		&accountID,
		utility.MarshalJSONOrEmpty(map[string]any{"client_id": clientID}),
		nil,
	))

	return nil
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
