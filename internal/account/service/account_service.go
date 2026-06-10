package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/google/uuid"
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

	// VerifyCredential verifies a credential (email/phone).
	VerifyCredential(ctx context.Context, accountID string) error

	// ChangePassword changes the account password.
	ChangePassword(ctx context.Context, accountID, oldPassword, newPassword string) error

	// BindFederatedIdentity binds a third-party identity to the account.
	BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]interface{}) error

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

type accountServiceImpl struct {
	db                    *sql.DB
	accountRepo           repository.AccountRepository
	credentialRepo        repository.CredentialRepository
	federatedIdentityRepo repository.FederatedIdentityRepository
	roleRepo              repository.RoleRepository
	auditor               *auditService.Auditor
	sessionRevoker        SessionRevoker
	oauth2ClientDeleter   OAuth2ClientDeleter
	logger                *zap.Logger
}

// AccountOption is a functional option for configuring AccountService.
type AccountOption func(*accountServiceImpl)

// WithSessionRevoker sets the session revoker dependency.
func WithSessionRevoker(revoker SessionRevoker) AccountOption {
	return func(s *accountServiceImpl) {
		if revoker == nil {
			panic("WithSessionRevoker: revoker must not be nil")
		}
		s.sessionRevoker = revoker
	}
}

// WithOAuth2ClientDeleter sets the OAuth2 client deleter dependency.
func WithOAuth2ClientDeleter(deleter OAuth2ClientDeleter) AccountOption {
	return func(s *accountServiceImpl) {
		if deleter == nil {
			panic("WithOAuth2ClientDeleter: deleter must not be nil")
		}
		s.oauth2ClientDeleter = deleter
	}
}

// NewAccountService creates the account service.
func NewAccountService(
	db *sql.DB,
	accountRepo repository.AccountRepository,
	credentialRepo repository.CredentialRepository,
	federatedIdentityRepo repository.FederatedIdentityRepository,
	roleRepo repository.RoleRepository,
	auditor *auditService.Auditor,
	logger *zap.Logger,
	opts ...AccountOption,
) AccountService {
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
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func (s *accountServiceImpl) setSessionRevoker(revoker SessionRevoker) {
	s.sessionRevoker = revoker
}

func (s *accountServiceImpl) setOAuth2ClientDeleter(deleter OAuth2ClientDeleter) {
	s.oauth2ClientDeleter = deleter
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

	// 2. Check if credentials already exist
	if req.Email != "" {
		if err := s.checkCredentialExists(ctx, domain.CredentialTypeEmail, req.Email); err != nil {
			return nil, err
		}
	}
	if req.Phone != "" {
		if err := s.checkCredentialExists(ctx, domain.CredentialTypePhone, req.Phone); err != nil {
			return nil, err
		}
	}

	// 3. Create account + credentials in transaction
	now := time.Now()

	var username *string
	if req.Username != "" {
		username = &req.Username
	}

	account := &domain.Account{
		ID:          uuid.New().String(),
		Username:    username,
		DisplayName: req.DisplayName,
		Status:      domain.AccountStatusActive,
		Locale:      req.Locale,
		Timezone:    req.Timezone,
		Metadata:    nonNilMap(req.Metadata),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.accountRepo.CreateAccount(ctx, tx, account); err != nil {
			return err
		}

		var credentials []*domain.Credential

		passwordHash, err := domain.HashPassword(req.Password)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		passwordCred := &domain.Credential{
			ID:                uuid.New().String(),
			AccountID:         account.ID,
			Type:              domain.CredentialTypePassword,
			Value:             passwordHash,
			Verified:          true,
			PrimaryCredential: false,
			Metadata:          make(map[string]interface{}),
			CreatedAt:         now,
		}
		credentials = append(credentials, passwordCred)

		if req.Email != "" {
			emailCred := &domain.Credential{
				ID:                uuid.New().String(),
				AccountID:         account.ID,
				Type:              domain.CredentialTypeEmail,
				Identifier:        &req.Email,
				Verified:          false,
				PrimaryCredential: true,
				Metadata:          make(map[string]interface{}),
				CreatedAt:         now,
			}
			credentials = append(credentials, emailCred)
		}

		if req.Phone != "" {
			phoneCred := &domain.Credential{
				ID:                uuid.New().String(),
				AccountID:         account.ID,
				Type:              domain.CredentialTypePhone,
				Identifier:        &req.Phone,
				Verified:          false,
				PrimaryCredential: req.Email == "",
				Metadata:          make(map[string]interface{}),
				CreatedAt:         now,
			}
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

	// 4. Audit log
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountRegister,
		audit.IPFromContext(ctx),
		stringPtr(account.ID),
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID}),
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

// UpdateAccount updates account information.
func (s *accountServiceImpl) UpdateAccount(ctx context.Context, account *domain.Account) error {
	account.UpdatedAt = time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.accountRepo.UpdateAccount(ctx, tx, account)
	})
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountUpdate,
		audit.IPFromContext(ctx),
		stringPtr(account.ID),
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// SoftDeleteAccount soft-deletes an account (cascades to all related data).
// Idempotent: returns nil if the account is already deleted.
func (s *accountServiceImpl) SoftDeleteAccount(ctx context.Context, accountID string) error {
	// 1. Validate request
	if accountID == "" {
		return errors.New("account ID is required")
	}

	// 2. Fail-fast: ensure dependencies are configured before starting the transaction
	if s.sessionRevoker == nil {
		return fmt.Errorf("%w: cannot revoke sessions on account deletion", ErrSessionRevokerNotBound)
	}
	if s.oauth2ClientDeleter == nil {
		return fmt.Errorf("%w: cannot cascade-delete OAuth2 clients", ErrOAuth2ClientDeleterNotBound)
	}

	// 3. Check if already deleted (idempotent)
	account, err := s.accountRepo.FindByID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("find account: %w", err)
	}
	if account.DeletedAt != nil {
		return nil
	}

	// 4. Soft-delete in transaction
	now := time.Now()
	txStart := time.Now()

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.credentialRepo.SoftDeleteCredentialsByAccount(ctx, tx, accountID, now); err != nil {
			return err
		}
		if err := s.federatedIdentityRepo.SoftDeleteByAccountID(ctx, tx, accountID, now); err != nil {
			return err
		}
		if err := s.roleRepo.SoftDeleteRolesByAccountID(ctx, tx, accountID, now); err != nil {
			return err
		}
		if err := s.oauth2ClientDeleter.SoftDeleteOAuth2ClientsByAccount(ctx, tx, accountID, now); err != nil {
			return err
		}
		return s.accountRepo.SoftDeleteAccount(ctx, tx, accountID, now)
	})
	txDuration := time.Since(txStart)
	if txDuration > 2*time.Second {
		s.logger.Warn("Slow account soft-delete transaction",
			zap.String("account_id", accountID),
			zap.Duration("duration", txDuration))
	}
	if err != nil {
		return err
	}

	// 5. Revoke all active sessions and refresh tokens.
	// Access tokens are invalidated by the JWT middleware's session existence check
	// (JWTAuthMiddleware validates sessions on every authenticated request), so explicit
	// blacklisting of access token JTIs is not required here.
	if revokeErr := s.sessionRevoker.RevokeAllForAccount(ctx, accountID); revokeErr != nil {
		s.logger.Error("Failed to revoke sessions after account deletion", zap.String("account_id", accountID), zap.Error(revokeErr))
	}

	// 6. Audit log (sync — critical security event)
	auditService.AuditLogSync(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountDelete,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// VerifyCredential verifies a credential.
func (s *accountServiceImpl) VerifyCredential(ctx context.Context, accountID string) error {
	// 1. Find credential
	credentials, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, domain.CredentialTypeEmail)
	if err != nil {
		if !errors.Is(err, repository.ErrCredentialNotFound) {
			return fmt.Errorf("find email credential: %w", err)
		}
	}
	if len(credentials) == 0 {
		// Try phone credential as fallback
		credentials, err = s.credentialRepo.FindByAccountAndType(ctx, accountID, domain.CredentialTypePhone)
		if err != nil {
			if !errors.Is(err, repository.ErrCredentialNotFound) {
				return fmt.Errorf("find phone credential: %w", err)
			}
		}
		if len(credentials) == 0 {
			return repository.ErrCredentialNotFound
		}
	}

	credential := credentials[0]

	// 2. Mark as verified
	credential.Verify()

	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateCredential(ctx, tx, credential)
	})
}

// ChangePassword changes the account password.
func (s *accountServiceImpl) ChangePassword(ctx context.Context, accountID, oldPassword, newPassword string) error {
	// 0. Ensure account is active
	if _, err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}

	// 1. Fail-fast: ensure session revoker is configured before modifying data
	if s.sessionRevoker == nil {
		return fmt.Errorf("%w: cannot revoke sessions on password change", ErrSessionRevokerNotBound)
	}

	// 2. Find password credential
	passwordCred, err := s.credentialRepo.FindPasswordCredential(ctx, accountID)
	if err != nil {
		return fmt.Errorf("find password credential: %w", err)
	}

	// 3. Verify old password
	if !passwordCred.VerifyPassword(oldPassword) {
		return ErrIncorrectOldPassword
	}

	// 4. Validate new password strength
	if err := utility.ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	// 5. Hash new password
	newPasswordHash, err := domain.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// 6. Update password
	passwordCred.Value = newPasswordHash

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateCredential(ctx, tx, passwordCred)
	})
	if err != nil {
		return err
	}

	// 7. Revoke all existing sessions so that any attacker with a stolen session is kicked out
	if revokeErr := s.sessionRevoker.RevokeAllForAccount(ctx, accountID); revokeErr != nil {
		s.logger.Error("Failed to revoke sessions after password change",
			zap.String("account_id", accountID), zap.Error(revokeErr))
	}

	// 8. Audit log (sync — critical security event)
	auditService.AuditLogSync(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionPasswordChange,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// BindFederatedIdentity binds a third-party identity.
func (s *accountServiceImpl) BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]interface{}) error {
	if _, err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}
	now := time.Now()
	identity := &domain.FederatedIdentity{
		ID:             uuid.New().String(),
		AccountID:      accountID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Profile:        profile,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Check inside transaction to reduce TOCTOU window.
		// FindByProvider uses the main DB connection (not tx), so two concurrent
		// requests may both pass this check. The DB unique constraint on
		// (provider, provider_user_id) is the authoritative guard — if the insert
		// fails with a unique violation, we look up the existing identity and
		// return ErrFederatedIdentityAlreadyBound instead of a raw DB error.
		existing, err := s.federatedIdentityRepo.FindByProvider(ctx, provider, providerUserID)
		if err == nil && existing != nil {
			return ErrFederatedIdentityAlreadyBound
		}
		return s.federatedIdentityRepo.CreateFederatedIdentity(ctx, tx, identity)
	})
	if err != nil {
		// Handle race condition: two concurrent requests both passed the
		// FindByProvider check. The unique constraint caught the duplicate —
		// look up the existing identity and return a clean business error.
		if dbutil.IsUniqueViolation(err) {
			existing, findErr := s.federatedIdentityRepo.FindByProvider(ctx, provider, providerUserID)
			if findErr == nil && existing != nil {
				if existing.AccountID == accountID {
					// Already bound to this account — idempotent success
					return nil
				}
				return ErrFederatedIdentityAlreadyBound
			}
		}
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionFederatedIdentityBind,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "provider": string(provider), "provider_user_id": providerUserID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// UnbindFederatedIdentity unbinds a third-party identity.
func (s *accountServiceImpl) UnbindFederatedIdentity(ctx context.Context, accountID, identityID string) error {
	if _, err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}
	now := time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.federatedIdentityRepo.SoftDeleteByID(ctx, tx, accountID, identityID, now)
	})
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionFederatedIdentityUnbind,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "identity_id": identityID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// AssignRole assigns a role to the account.
func (s *accountServiceImpl) AssignRole(ctx context.Context, accountID, roleID string) error {
	if _, err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.roleRepo.AssignRoleToAccount(ctx, tx, accountID, roleID)
	})
	if err != nil {
		return err
	}

	auditService.AuditLogSync(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionRoleAssign,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "role_id": roleID}),
		auditMetaFromContext(ctx),
	))
	return nil
}

// RemoveRole removes a role from the account.
func (s *accountServiceImpl) RemoveRole(ctx context.Context, accountID, roleID string) error {
	if _, err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}
	now := time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.roleRepo.RemoveRoleFromAccount(ctx, tx, accountID, roleID, now)
	})
	if err != nil {
		return err
	}

	auditService.AuditLogSync(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionRoleRemove,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "role_id": roleID}),
		auditMetaFromContext(ctx),
	))
	return nil
}

// ListAccounts returns a paginated list of accounts.
func (s *accountServiceImpl) ListAccounts(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error) {
	return s.accountRepo.FindAll(ctx, page, pageSize, status)
}

// SuspendAccount suspends the account atomically.
func (s *accountServiceImpl) SuspendAccount(ctx context.Context, accountID string) error {
	// Fail-fast: ensure session revoker is configured before modifying data
	if s.sessionRevoker == nil {
		return fmt.Errorf("%w: cannot revoke sessions on account suspension", ErrSessionRevokerNotBound)
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.accountRepo.SuspendAccount(ctx, tx, accountID)
	})
	if err != nil {
		return err
	}

	// Revoke all active sessions so the suspended user loses access immediately
	if revokeErr := s.sessionRevoker.RevokeAllForAccount(ctx, accountID); revokeErr != nil {
		s.logger.Error("Failed to revoke sessions after account suspension",
			zap.String("account_id", accountID), zap.Error(revokeErr))
	}

	auditService.AuditLogSync(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountSuspend,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))
	return nil
}

// ActivateAccount reactivates the account atomically.
func (s *accountServiceImpl) ActivateAccount(ctx context.Context, accountID string) error {
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.accountRepo.ActivateAccount(ctx, tx, accountID)
	})
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountActivate,
		audit.IPFromContext(ctx),
		stringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))
	return nil
}

// GetAccountRoles returns the roles assigned to the account.
func (s *accountServiceImpl) GetAccountRoles(ctx context.Context, accountID string) ([]*domain.Role, error) {
	return s.roleRepo.FindRolesByAccountID(ctx, accountID)
}

// validateRegistration validates the registration request.
func (s *accountServiceImpl) validateRegistration(req *RegisterAccountRequest) error {
	if req.Password == "" {
		return errors.New("password is required")
	}

	if err := utility.ValidatePasswordStrength(req.Password); err != nil {
		return err
	}

	if req.Email == "" && req.Phone == "" {
		return errors.New("at least one of email or phone is required")
	}

	if req.DisplayName == "" {
		return errors.New("display name is required")
	}

	// Validate email format
	if req.Email != "" {
		addr, err := mail.ParseAddress(req.Email)
		if err != nil || addr.Address != req.Email {
			return errors.New("invalid email format")
		}
	}

	// Validate phone format
	if req.Phone != "" {
		if !utility.ValidatePhoneFormat(req.Phone) {
			return errors.New("invalid phone format")
		}
	}

	return nil
}

// checkCredentialExists checks whether a credential with the given type and identifier already exists.
func (s *accountServiceImpl) checkCredentialExists(ctx context.Context, credType domain.CredentialType, identifier string) error {
	cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, credType, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrCredentialNotFound) {
			return nil
		}
		return fmt.Errorf("check credential existence: %w", err)
	}
	if cred != nil {
		switch credType {
		case domain.CredentialTypeEmail:
			return ErrEmailAlreadyRegistered
		case domain.CredentialTypePhone:
			return ErrPhoneAlreadyRegistered
		}
	}
	return nil
}

func stringPtr(s string) *string {
	return &s
}

// auditMetaFromContext extracts IP and user-agent from context for audit logging.
func auditMetaFromContext(ctx context.Context) json.RawMessage {
	return utility.MustMarshalJSON(map[string]any{
		"ip":         audit.IPFromContext(ctx),
		"user_agent": audit.UserAgentFromContext(ctx),
	})
}

// nonNilMap returns m if non-nil, otherwise an empty map.
// Prevents nil-map panics and ensures JSON serialization produces {} instead of null.
func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return make(map[string]any)
	}
	return m
}

// classifyRegistrationConflict determines the specific conflict cause when a
// registration unique constraint violation occurs. It checks credential
// existence to return a precise business error.
func (s *accountServiceImpl) classifyRegistrationConflict(ctx context.Context, req *RegisterAccountRequest) error {
	// Check email credential first (most common conflict)
	if req.Email != "" {
		cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, domain.CredentialTypeEmail, req.Email)
		if err == nil && cred != nil {
			return ErrEmailAlreadyRegistered
		}
	}
	// Check phone credential
	if req.Phone != "" {
		cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, domain.CredentialTypePhone, req.Phone)
		if err == nil && cred != nil {
			return ErrPhoneAlreadyRegistered
		}
	}
	// If neither credential conflicts, it must be a username conflict
	return ErrUsernameAlreadyTaken
}
