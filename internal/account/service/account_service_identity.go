package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/utility"
)

// BindFederatedIdentity binds a third-party identity.
func (s *accountServiceImpl) BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]any) error {
	identity, err := domain.NewFederatedIdentity(accountID, provider, providerUserID, profile)
	if err != nil {
		return fmt.Errorf("create federated identity: %w", err)
	}

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Verify account is active inside the transaction to prevent TOCTOU:
		// the account could be soft-deleted or suspended between the check and the insert.
		account, findErr := s.accountRepo.FindByIDTx(ctx, tx, accountID)
		if findErr != nil {
			return findErr
		}
		if !account.IsActive() {
			return ErrAccountNotActive
		}

		// Check inside the transaction to avoid TOCTOU: a concurrent request
		// could bind the same identity between our check and the insert.
		existing, providerErr := s.federatedIdentityRepo.FindByProviderTx(ctx, tx, provider, providerUserID)
		if providerErr == nil && existing != nil {
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
		utility.Ptr[string](accountID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": accountID, "provider": string(provider), "provider_user_id": providerUserID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// UnbindFederatedIdentity unbinds a third-party identity.
// Prevents unbinding the last authentication method if the account has no password.
// The check and deletion are performed atomically within a transaction to prevent TOCTOU races.
func (s *accountServiceImpl) UnbindFederatedIdentity(ctx context.Context, accountID, identityID string) error {
	now := time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Verify account is active inside the transaction to prevent TOCTOU:
		// the account could be soft-deleted between the check and the write.
		account, err := s.accountRepo.FindByIDTx(ctx, tx, accountID)
		if err != nil {
			if errors.Is(err, repository.ErrAccountNotFound) {
				return ErrAccountNotActive
			}
			return err
		}
		if !account.IsActive() {
			return ErrAccountNotActive
		}

		// Check that unbinding won't lock the user out: they must have either a password
		// or at least one other federated identity remaining.
		hasPassword := false
		pwCreds, err := s.credentialRepo.FindByAccountAndTypeTx(ctx, tx, accountID, domain.CredentialTypePassword)
		if err != nil {
			return fmt.Errorf("check password credential: %w", err)
		}
		for _, c := range pwCreds {
			if !c.IsDeleted() {
				hasPassword = true
				break
			}
		}
		if !hasPassword {
			identities, err := s.federatedIdentityRepo.FindByAccountIDTx(ctx, tx, accountID)
			if err != nil {
				return fmt.Errorf("check federated identities: %w", err)
			}
			activeCount := 0
			for _, id := range identities {
				if !id.IsDeleted() && id.ID != identityID {
					activeCount++
				}
			}
			if activeCount == 0 {
				return ErrCannotUnbindLastAuthMethod
			}
		}

		return s.federatedIdentityRepo.SoftDeleteFederatedIdentityByID(ctx, tx, accountID, identityID, now)
	})
	if err != nil {
		return err
	}

	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionFederatedIdentityUnbind,
		audit.IPFromContext(ctx),
		utility.Ptr[string](accountID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": accountID, "identity_id": identityID}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// AssignRole assigns a role to the account.
func (s *accountServiceImpl) AssignRole(ctx context.Context, accountID, roleID string) error {
	// Verify role exists and assign atomically. Account activity is checked inside
	// the transaction to prevent TOCTOU: the account could be soft-deleted between
	// the check and the write.
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		account, err := s.accountRepo.FindByIDTx(ctx, tx, accountID)
		if err != nil {
			if errors.Is(err, repository.ErrAccountNotFound) {
				return ErrAccountNotActive
			}
			return err
		}
		if !account.IsActive() {
			return ErrAccountNotActive
		}
		role, err := s.roleRepo.FindByIDTx(ctx, tx, roleID)
		if err != nil {
			return err
		}
		if role.IsDeleted() {
			return repository.ErrRoleNotFound
		}
		return s.roleRepo.AssignRoleToAccount(ctx, tx, accountID, roleID, time.Now())
	})
	if err != nil {
		return err
	}

	// Invalidate cached roles so the next token build fetches fresh data.
	if s.roleCacheInvalidator != nil {
		if invErr := s.roleCacheInvalidator.InvalidateRoleCache(ctx, accountID); invErr != nil {
			s.logger.Warn("Failed to invalidate role cache after AssignRole",
				zap.String("account_id", accountID), zap.Error(invErr))
		}
	}

	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionRoleAssign,
		audit.IPFromContext(ctx),
		utility.Ptr[string](accountID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": accountID, "role_id": roleID}),
		auditMetaFromContext(ctx),
	))
	return nil
}

// RemoveRole removes a role from the account.
func (s *accountServiceImpl) RemoveRole(ctx context.Context, accountID, roleID string) error {
	now := time.Now()

	// Account activity is checked inside the transaction to prevent TOCTOU.
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		account, err := s.accountRepo.FindByIDTx(ctx, tx, accountID)
		if err != nil {
			if errors.Is(err, repository.ErrAccountNotFound) {
				return ErrAccountNotActive
			}
			return err
		}
		if !account.IsActive() {
			return ErrAccountNotActive
		}
		return s.roleRepo.RemoveRoleFromAccount(ctx, tx, accountID, roleID, now)
	})
	if err != nil {
		return err
	}

	// Invalidate cached roles so the next token build fetches fresh data.
	if s.roleCacheInvalidator != nil {
		if invErr := s.roleCacheInvalidator.InvalidateRoleCache(ctx, accountID); invErr != nil {
			s.logger.Warn("Failed to invalidate role cache after RemoveRole",
				zap.String("account_id", accountID), zap.Error(invErr))
		}
	}

	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionRoleRemove,
		audit.IPFromContext(ctx),
		utility.Ptr[string](accountID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": accountID, "role_id": roleID}),
		auditMetaFromContext(ctx),
	))
	return nil
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
		return domain.ErrDisplayNameRequired
	}

	// Validate email format
	if req.Email != "" {
		addr, err := mail.ParseAddress(req.Email)
		if err != nil || addr.Address != req.Email {
			return domain.ErrInvalidEmailFormat
		}
	}

	// Validate phone format
	if req.Phone != "" {
		if !utility.ValidatePhoneFormat(req.Phone) {
			return domain.ErrInvalidPhoneFormat
		}
	}

	return nil
}

// validateUsername validates a username string.
// Username must be non-empty, at least 2 characters, at most 64 characters,
// and contain only lowercase letters, digits, hyphens, dots, and underscores.
// The 64-character limit matches domain.ErrUsernameTooLong.
func validateUsername(username string) error {
	if username == "" {
		return ErrUsernameEmpty
	}
	if len(username) < 2 {
		return ErrUsernameTooShort
	}
	if len(username) > 64 {
		return ErrUsernameTooLong
	}
	for _, c := range username {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return ErrUsernameInvalidChars
		}
	}
	return nil
}

// checkCredentialExistsTx is the transaction-variant of checkCredentialExists.
// Use inside RunInTransaction to avoid TOCTOU race conditions.
func (s *accountServiceImpl) checkCredentialExistsTx(ctx context.Context, tx *sql.Tx, credType domain.CredentialType, identifier string) error {
	cred, err := s.credentialRepo.FindByTypeAndIdentifierTx(ctx, tx, credType, identifier)
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
		case domain.CredentialTypePassword, domain.CredentialTypeTOTP, domain.CredentialTypeWebAuthn, domain.CredentialTypeBackupCode:
			return fmt.Errorf("%w: %s", ErrCredentialAlreadyExists, credType)
		}
	}
	return nil
}

// auditMetaFromContext extracts IP and user-agent from context for audit logging.
func auditMetaFromContext(ctx context.Context) json.RawMessage {
	return utility.MarshalJSONOrEmpty(map[string]any{
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
//
// NOTE: This method queries outside the failed transaction, so under concurrent
// registrations the classified error type may be slightly imprecise (e.g., a
// phone conflict could be reported as a username conflict if the concurrent
// insert commits between the transaction failure and this query). The impact is
// limited to the user-facing error message — no data integrity is affected.
func (s *accountServiceImpl) classifyRegistrationConflict(ctx context.Context, req *RegisterAccountRequest) error {
	// Run email and phone credential lookups concurrently to reduce latency
	// on this error path. Both queries are independent reads outside the
	// failed transaction, so parallelizing them is safe.
	type credResult struct {
		cred *domain.Credential
		err  error
	}

	g, gctx := errgroup.WithContext(ctx)

	var emailResult, phoneResult credResult

	if req.Email != "" {
		g.Go(func() error {
			emailResult.cred, emailResult.err = s.credentialRepo.FindByTypeAndIdentifier(gctx, domain.CredentialTypeEmail, req.Email)
			return nil // lookup errors are non-fatal; fall through to username conflict
		})
	}
	if req.Phone != "" {
		g.Go(func() error {
			phoneResult.cred, phoneResult.err = s.credentialRepo.FindByTypeAndIdentifier(gctx, domain.CredentialTypePhone, req.Phone)
			return nil // lookup errors are non-fatal; fall through to username conflict
		})
	}
	if err := g.Wait(); err != nil {
		return ErrUsernameAlreadyTaken
	}

	// Check email first (most common conflict), then phone
	if req.Email != "" && emailResult.err == nil && emailResult.cred != nil {
		return ErrEmailAlreadyRegistered
	}
	if req.Phone != "" && phoneResult.err == nil && phoneResult.cred != nil {
		return ErrPhoneAlreadyRegistered
	}
	// If neither credential conflicts, it must be a username conflict
	return ErrUsernameAlreadyTaken
}

// ResetMFA soft-deletes all TOTP, WebAuthn (Passkeys) and BackupCode credentials for the account.
func (s *accountServiceImpl) ResetMFA(ctx context.Context, accountID string) error {
	_, err := s.accountRepo.FindByID(ctx, accountID)
	if err != nil {
		return err
	}

	now := time.Now()
	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Soft delete TOTP credentials
		if err := s.credentialRepo.SoftDeleteCredentialsByType(ctx, tx, accountID, domain.CredentialTypeTOTP, now); err != nil {
			return fmt.Errorf("delete totp: %w", err)
		}
		// Soft delete Backup Code credentials
		if err := s.credentialRepo.SoftDeleteCredentialsByType(ctx, tx, accountID, domain.CredentialTypeBackupCode, now); err != nil {
			return fmt.Errorf("delete backup codes: %w", err)
		}
		// Soft delete WebAuthn (Passkey) credentials
		if err := s.credentialRepo.SoftDeleteCredentialsByType(ctx, tx, accountID, domain.CredentialTypeWebAuthn, now); err != nil {
			return fmt.Errorf("delete webauthn: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Write audit log
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionMFADisable,
		audit.IPFromContext(ctx),
		utility.Ptr[string](accountID),
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": accountID, "reset_by": "admin"}),
		auditMetaFromContext(ctx),
	))

	return nil
}

