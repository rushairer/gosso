package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/utility"
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
	UnbindFederatedIdentity(ctx context.Context, identityID string) error

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

// NewAccountService creates the account service.
func NewAccountService(
	db *sql.DB,
	accountRepo repository.AccountRepository,
	credentialRepo repository.CredentialRepository,
	federatedIdentityRepo repository.FederatedIdentityRepository,
	roleRepo repository.RoleRepository,
	auditor *auditService.Auditor,
	logger *zap.Logger,
) AccountService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &accountServiceImpl{
		db:                    db,
		accountRepo:           accountRepo,
		credentialRepo:        credentialRepo,
		federatedIdentityRepo: federatedIdentityRepo,
		roleRepo:              roleRepo,
		auditor:               auditor,
		logger:                logger,
	}
}

// SetSessionRevoker sets the session revoker dependency (setter injection).
func (s *accountServiceImpl) SetSessionRevoker(revoker SessionRevoker) {
	s.sessionRevoker = revoker
}

// SetOAuth2ClientDeleter sets the OAuth2 client deleter dependency (setter injection).
func (s *accountServiceImpl) SetOAuth2ClientDeleter(deleter OAuth2ClientDeleter) {
	s.oauth2ClientDeleter = deleter
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
	if req.Username != "" {
		existing, err := s.FindAccountByUsername(ctx, req.Username)
		if err == nil && existing != nil {
			return nil, fmt.Errorf("username already taken")
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
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.accountRepo.CreateAccount(ctx, tx, account); err != nil {
			return err
		}

		var credentials []*domain.Credential

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		passwordCred := &domain.Credential{
			ID:                uuid.New().String(),
			AccountID:         account.ID,
			Type:              domain.CredentialTypePassword,
			Value:             string(passwordHash),
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
		return nil, err
	}

	// 8. Audit log
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountRegister,
		audit.IPFromContext(ctx),
		parseUUID(account.ID),
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
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

	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.accountRepo.UpdateAccount(ctx, tx, account)
	})
}

// SoftDeleteAccount soft-deletes an account (cascades to all related data).
func (s *accountServiceImpl) SoftDeleteAccount(ctx context.Context, accountID string) error {
	// 1. Validate request
	if accountID == "" {
		return errors.New("account ID is required")
	}

	// 2. Soft-delete in transaction
	now := time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.credentialRepo.SoftDeleteCredentialsByAccount(ctx, tx, accountID, now); err != nil {
			return err
		}
		if err := s.federatedIdentityRepo.SoftDeleteByAccountID(ctx, tx, accountID, now); err != nil {
			return err
		}
		if err := s.roleRepo.SoftDeleteRolesByAccountID(ctx, tx, accountID, now); err != nil {
			return err
		}
		if s.oauth2ClientDeleter != nil {
			if err := s.oauth2ClientDeleter.SoftDeleteOAuth2ClientsByAccount(ctx, tx, accountID, now); err != nil {
				return err
			}
		} else {
			s.logger.Warn("OAuth2ClientDeleter not set, skipping OAuth2 client cascade on account deletion", zap.String("account_id", accountID))
		}
		return s.accountRepo.SoftDeleteAccount(ctx, tx, accountID, now)
	})
	if err != nil {
		return err
	}

	// 3. Revoke all active sessions and refresh tokens.
	// Access tokens are invalidated by the JWT middleware's session existence check
	// (JWTAuthMiddleware validates sessions on every authenticated request), so explicit
	// blacklisting of access token JTIs is not required here.
	if s.sessionRevoker != nil {
		if revokeErr := s.sessionRevoker.RevokeAllForAccount(ctx, accountID); revokeErr != nil {
			s.logger.Error("Failed to revoke sessions after account deletion", zap.String("account_id", accountID), zap.Error(revokeErr))
		}
	} else {
		s.logger.Warn("SessionRevoker not set, skipping session revocation on account deletion", zap.String("account_id", accountID))
	}

	// 4. Audit log
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountDelete,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
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
			return errors.New("credential not found")
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
	// 1. Find password credential
	passwordCred, err := s.credentialRepo.FindPasswordCredential(ctx, accountID)
	if err != nil {
		return fmt.Errorf("find password credential: %w", err)
	}

	// 2. Verify old password
	if !passwordCred.VerifyPassword(oldPassword) {
		return errors.New("incorrect old password")
	}

	// 3. Hash new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// 4. Update password
	passwordCred.Value = string(newPasswordHash)

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateCredential(ctx, tx, passwordCred)
	})
	if err != nil {
		return err
	}

	// 5. Revoke all existing sessions so that any attacker with a stolen session is kicked out
	if s.sessionRevoker != nil {
		if revokeErr := s.sessionRevoker.RevokeAllForAccount(ctx, accountID); revokeErr != nil {
			s.logger.Error("Failed to revoke sessions after password change",
				zap.String("account_id", accountID), zap.Error(revokeErr))
		}
	} else {
		s.logger.Warn("SessionRevoker not set, skipping session revocation on password change",
			zap.String("account_id", accountID))
	}

	// 6. Audit log
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionPasswordChange,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return nil
}

// BindFederatedIdentity binds a third-party identity.
func (s *accountServiceImpl) BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]interface{}) error {
	// 1. Check if already bound
	existing, err := s.federatedIdentityRepo.FindByProvider(ctx, provider, providerUserID)
	if err == nil && existing != nil {
		return errors.New("federated identity already bound")
	}

	// 2. Create binding
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

	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.federatedIdentityRepo.CreateFederatedIdentity(ctx, tx, identity)
	})
}

// UnbindFederatedIdentity unbinds a third-party identity.
func (s *accountServiceImpl) UnbindFederatedIdentity(ctx context.Context, identityID string) error {
	now := time.Now()

	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.federatedIdentityRepo.SoftDeleteByID(ctx, tx, identityID, now)
	})
}

// AssignRole assigns a role to the account.
func (s *accountServiceImpl) AssignRole(ctx context.Context, accountID, roleID string) error {
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.roleRepo.AssignRoleToAccount(ctx, tx, accountID, roleID)
	})
	if err != nil {
		return err
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionRoleAssign,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "role_id": roleID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// RemoveRole removes a role from the account.
func (s *accountServiceImpl) RemoveRole(ctx context.Context, accountID, roleID string) error {
	now := time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.roleRepo.RemoveRoleFromAccount(ctx, tx, accountID, roleID, now)
	})
	if err != nil {
		return err
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionRoleRemove,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "role_id": roleID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// ListAccounts returns a paginated list of accounts.
func (s *accountServiceImpl) ListAccounts(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error) {
	return s.accountRepo.FindAll(ctx, page, pageSize, status)
}

// SuspendAccount suspends the account atomically.
func (s *accountServiceImpl) SuspendAccount(ctx context.Context, accountID string) error {
	if err := s.accountRepo.SuspendAccount(ctx, accountID); err != nil {
		return err
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountSuspend,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// ActivateAccount reactivates the account atomically.
func (s *accountServiceImpl) ActivateAccount(ctx context.Context, accountID string) error {
	if err := s.accountRepo.ActivateAccount(ctx, accountID); err != nil {
		return err
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountActivate,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// GetAccountRoles returns the roles assigned to the account.
func (s *accountServiceImpl) GetAccountRoles(ctx context.Context, accountID string) ([]*domain.Role, error) {
	return s.roleRepo.FindRolesByAccountID(ctx, accountID)
}

// validateRegistration validates the registration request.
var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{6,14}$`)

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
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return errors.New("invalid email format")
		}
	}

	// Validate phone format
	if req.Phone != "" {
		if !phoneRegex.MatchString(req.Phone) {
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
			return errors.New("email already registered")
		case domain.CredentialTypePhone:
			return errors.New("phone already registered")
		}
	}
	return nil
}

func (s *accountServiceImpl) auditLog(ctx context.Context, record *auditDomain.AuditRecord) {
	if s.auditor != nil {
		if err := s.auditor.Log(ctx, record); err != nil {
			s.logger.Warn("Failed to submit audit record", zap.Error(err))
		}
	}
}

func parseUUID(s string) *uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}
