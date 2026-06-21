package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/utility"
)

// AccountService defines the account service interface.
type AccountService interface {
	// RegisterAccount registers a new account (email/phone + password).
	RegisterAccount(ctx context.Context, req *RegisterAccountRequest) (*domain.Account, error)

	// FindAccountByID finds an account by its ID.
	FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error)

	// FindAccountByUsername finds an account by its username.
	FindAccountByUsername(ctx context.Context, username string) (*domain.Account, error)

	// UpdateAccount updates account information.
	UpdateAccount(ctx context.Context, account *domain.Account) error

	// SoftDeleteAccount soft-deletes an account (cascades to all related data).
	SoftDeleteAccount(ctx context.Context, accountID string) error

	// VerifyContactCredential verifies the account's primary contact credential (email first, phone fallback).
	VerifyContactCredential(ctx context.Context, accountID string) error

	// ChangePassword changes the account password.
	ChangePassword(ctx context.Context, accountID, oldPassword, newPassword string) error

	// BindFederatedIdentity binds a third-party identity to the account.
	BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]any) error

	// UnbindFederatedIdentity unbinds a third-party identity from the account.
	UnbindFederatedIdentity(ctx context.Context, accountID, identityID string) error

	// AssignRole assigns a role to the account.
	AssignRole(ctx context.Context, accountID, roleID string) error

	// RemoveRole removes a role from the account.
	RemoveRole(ctx context.Context, accountID, roleID string) error

	// ListAccounts returns a paginated list of accounts (admin use).
	ListAccounts(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error)

	// SuspendAccount suspends the account.
	SuspendAccount(ctx context.Context, accountID string) error

	// ActivateAccount reactivates the account.
	ActivateAccount(ctx context.Context, accountID string) error

	// GetAccountRoles returns the roles assigned to the account.
	GetAccountRoles(ctx context.Context, accountID string) ([]*domain.Role, error)

	// SetOptions configures optional cross-module dependencies.
	// Must be called during initialization before any dependent operations.
	// The call is atomic: all fields in opts are applied together.
	SetOptions(opts *AccountServiceOptions)
}

// RegisterAccountRequest is the request payload for account registration.
type RegisterAccountRequest struct {
	Username    string         // optional username
	DisplayName string         // display name
	Email       string         // optional email
	Phone       string         // optional phone number
	Password    string         // required password
	Locale      string         // language preference
	Timezone    string         // timezone
	Metadata    map[string]any // extra metadata
}

// SessionRevoker revokes all sessions and tokens for an account.
type SessionRevoker interface {
	RevokeAllForAccount(ctx context.Context, accountID string) error
}

// OAuth2ClientDeleter soft-deletes all OAuth2 clients for an account.
type OAuth2ClientDeleter interface {
	SoftDeleteOAuth2ClientsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
}

// ConsentCacheInvalidator clears consent cache entries for an account.
type ConsentCacheInvalidator interface {
	DeleteConsentsByAccount(ctx context.Context, accountID string) error
}

// AccountServiceOptions holds optional dependencies for NewAccountService.
// All fields are optional — nil values are handled at runtime with safe fallbacks.
type AccountServiceOptions struct {
	SessionRevoker          SessionRevoker          // required for SoftDelete/ChangePassword/Suspend
	OAuth2ClientDeleter     OAuth2ClientDeleter     // required for SoftDelete
	ConsentCacheInvalidator ConsentCacheInvalidator // optional, non-critical
}

type accountServiceImpl struct {
	db                      *sql.DB
	accountRepo             repository.AccountRepository
	credentialRepo          repository.CredentialRepository
	federatedIdentityRepo   repository.FederatedIdentityRepository
	roleRepo                repository.RoleRepository
	auditor                 *auditService.Auditor
	sessionRevoker          SessionRevoker
	oauth2ClientDeleter     OAuth2ClientDeleter
	consentCacheInvalidator ConsentCacheInvalidator
	logger                  *zap.Logger
	optionsOnce             sync.Once
	setOptionsCalls         atomic.Int32
}

// auditLogSync writes an audit record synchronously and logs any error.
// Used for critical security events where loss on crash is unacceptable.
func (s *accountServiceImpl) auditLogSync(ctx context.Context, record *auditDomain.AuditRecord) {
	if err := auditService.AuditLogSync(ctx, s.auditor, s.logger, record); err != nil {
		s.logger.Error("Failed to write sync audit log", zap.Error(err))
	}
}

// NewAccountService creates the account service.
// opts may be nil; optional dependencies can be set via AccountServiceOptions.
func NewAccountService(
	db *sql.DB,
	accountRepo repository.AccountRepository,
	credentialRepo repository.CredentialRepository,
	federatedIdentityRepo repository.FederatedIdentityRepository,
	roleRepo repository.RoleRepository,
	auditor *auditService.Auditor,
	logger *zap.Logger,
	opts *AccountServiceOptions,
) *accountServiceImpl {
	logger = utility.EnsureLogger(logger)
	svc := &accountServiceImpl{
		db:                    db,
		accountRepo:           accountRepo,
		credentialRepo:        credentialRepo,
		federatedIdentityRepo: federatedIdentityRepo,
		roleRepo:              roleRepo,
		auditor:               auditor,
		logger:                logger,
	}
	if opts != nil {
		svc.sessionRevoker = opts.SessionRevoker
		svc.oauth2ClientDeleter = opts.OAuth2ClientDeleter
		svc.consentCacheInvalidator = opts.ConsentCacheInvalidator
	}
	return svc
}

// SetOptions configures optional cross-module dependencies.
// Thread-safe: uses sync.Once to ensure configuration happens exactly once.
// Subsequent calls are logged as warnings and ignored.
func (s *accountServiceImpl) SetOptions(opts *AccountServiceOptions) {
	if opts == nil {
		return
	}
	if s.setOptionsCalls.Add(1) > 1 && s.logger != nil {
		s.logger.Warn("SetOptions called multiple times; subsequent calls are ignored",
			zap.Int32("call_count", s.setOptionsCalls.Load()))
	}
	s.optionsOnce.Do(func() {
		s.sessionRevoker = opts.SessionRevoker
		s.oauth2ClientDeleter = opts.OAuth2ClientDeleter
		s.consentCacheInvalidator = opts.ConsentCacheInvalidator
	})
}

// requireActiveAccount looks up an account by ID and returns it only if it exists and is active.
func (s *accountServiceImpl) requireActiveAccount(ctx context.Context, accountID string) (*domain.Account, error) {
	account, err := s.accountRepo.FindByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, repository.ErrAccountNotFound) {
			return nil, ErrAccountNotActive
		}
		return nil, err
	}
	if !account.IsActive() {
		return nil, ErrAccountNotActive
	}
	return account, nil
}

// RegisterAccount registers a new account.
func (s *accountServiceImpl) RegisterAccount(ctx context.Context, req *RegisterAccountRequest) (*domain.Account, error) {
	// 1. Validate request
	if err := s.validateRegistration(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// 2. Create account + credentials in transaction
	account, err := domain.NewAccount(req.DisplayName)
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}
	if req.Username != "" {
		username := strings.TrimSpace(req.Username)
		if err := validateUsername(username); err != nil {
			return nil, err
		}
		account.Username = &username
	}
	if req.Locale != "" {
		account.Locale = strings.TrimSpace(req.Locale)
	}
	if req.Timezone != "" {
		tz := strings.TrimSpace(req.Timezone)
		if _, err := time.LoadLocation(tz); err != nil {
			return nil, fmt.Errorf("invalid timezone: %s", tz)
		}
		account.Timezone = tz
	}
	account.Metadata = nonNilMap(req.Metadata)

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Check credential uniqueness inside the transaction to eliminate TOCTOU window.
		if req.Email != "" {
			if err := s.checkCredentialExistsTx(ctx, tx, domain.CredentialTypeEmail, req.Email); err != nil {
				return err
			}
		}
		if req.Phone != "" {
			if err := s.checkCredentialExistsTx(ctx, tx, domain.CredentialTypePhone, req.Phone); err != nil {
				return err
			}
		}

		if err := s.accountRepo.CreateAccount(ctx, tx, account); err != nil {
			return err
		}

		var credentials []*domain.Credential

		passwordCred, err := domain.NewPasswordCredential(account.ID, req.Password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		credentials = append(credentials, passwordCred)

		if req.Email != "" {
			emailCred, err := domain.NewEmailCredential(account.ID, req.Email)
			if err != nil {
				return fmt.Errorf("create email credential: %w", err)
			}
			emailCred.PrimaryCredential = true
			credentials = append(credentials, emailCred)
		}

		if req.Phone != "" {
			phoneCred, err := domain.NewPhoneCredential(account.ID, req.Phone)
			if err != nil {
				return fmt.Errorf("create phone credential: %w", err)
			}
			phoneCred.PrimaryCredential = req.Email == ""
			credentials = append(credentials, phoneCred)
		}

		return s.credentialRepo.CreateCredentials(ctx, tx, credentials)
	})
	if err != nil {
		// Unique constraint violation: differentiate between username, email, and phone conflicts.
		// The unique constraint can come from accounts.username or account_credentials (credential_type, identifier).
		if dbutil.IsUniqueViolation(err) {
			return nil, s.classifyRegistrationConflict(ctx, req)
		}
		return nil, err
	}

	// 3. Audit log (sync: account creation is a security-critical event)
	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountRegister,
		audit.IPFromContext(ctx),
		utility.Ptr[string](account.ID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": account.ID}),
		auditMetaFromContext(ctx),
	))

	return account, nil
}

// FindAccountByID finds an account by ID.
func (s *accountServiceImpl) FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error) {
	return s.accountRepo.FindByID(ctx, accountID)
}

// FindAccountByUsername finds an account by username.
func (s *accountServiceImpl) FindAccountByUsername(ctx context.Context, username string) (*domain.Account, error) {
	return s.accountRepo.FindByUsername(ctx, username)
}

// UpdateAccount updates account information with optimistic locking.
// The update only succeeds if the account has not been modified since it was
// last read by the caller. Returns ErrConcurrentModification on races.
func (s *accountServiceImpl) UpdateAccount(ctx context.Context, account *domain.Account) error {
	account.Sanitize()
	if err := account.Validate(); err != nil {
		return fmt.Errorf("invalid account: %w", err)
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Re-read inside the transaction to get a consistent snapshot of updated_at
		current, err := s.accountRepo.FindByIDTx(ctx, tx, account.ID)
		if err != nil {
			return err
		}
		expectedUpdatedAt := current.UpdatedAt
		account.UpdatedAt = time.Now()
		return s.accountRepo.UpdateAccount(ctx, tx, account, expectedUpdatedAt)
	})
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountUpdate,
		audit.IPFromContext(ctx),
		utility.Ptr[string](account.ID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": account.ID}),
		auditMetaFromContext(ctx),
	))

	return nil
}
