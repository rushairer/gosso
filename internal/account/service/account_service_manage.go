package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/utility"
)

// SoftDeleteAccount soft-deletes an account (cascades to all related data).
// Idempotent: returns nil if the account is already deleted.
func (s *accountServiceImpl) SoftDeleteAccount(ctx context.Context, accountID string) error {
	// 1. Validate request
	if accountID == "" {
		return domain.ErrAccountIDRequired
	}

	// 2. Fail-fast: ensure dependencies are configured before starting the transaction
	if s.sessionRevoker == nil {
		return fmt.Errorf("%w: cannot revoke sessions on account deletion", ErrSessionRevokerNotBound)
	}
	if s.oauth2ClientDeleter == nil {
		return fmt.Errorf("%w: cannot cascade-delete OAuth2 clients", ErrOAuth2ClientDeleterNotBound)
	}

	// 3. Soft-delete in transaction (includes idempotency check to prevent concurrent deletion)
	now := time.Now()
	txStart := time.Now()

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Re-check inside transaction to prevent concurrent deletion
		account, err := s.accountRepo.FindByIDIncludingDeletedTx(ctx, tx, accountID)
		if err != nil {
			return fmt.Errorf("find account: %w", err)
		}
		if account.DeletedAt != nil {
			return nil // idempotent
		}

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

	// 4. Revoke all active sessions and refresh tokens.
	// Access tokens are invalidated by the JWT middleware's session existence check
	// (JWTAuthMiddleware validates sessions on every authenticated request), so explicit
	// blacklisting of access token JTIs is not required here.
	var revokeErr error
	if revokeErr = s.sessionRevoker.RevokeAllForAccount(ctx, accountID); revokeErr != nil {
		s.logger.Error("Failed to revoke sessions after account deletion", zap.String("account_id", accountID), zap.Error(revokeErr))
	}

	// 5. Clear consent cache entries for this account.
	// This prevents stale cached consents from surviving after account deletion.
	// Failure is non-critical since the consent TTL (90 days) will expire naturally.
	if s.consentCacheInvalidator != nil {
		if err := s.consentCacheInvalidator.DeleteConsentsByAccount(ctx, accountID); err != nil {
			s.logger.Warn("Failed to clear consent cache after account deletion",
				zap.String("account_id", accountID), zap.Error(err))
		}
	}

	// 6. Audit log (sync — critical security event)
	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountDelete,
		audit.IPFromContext(ctx),
		utility.StringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))

	if revokeErr != nil {
		return fmt.Errorf("account deleted but session revocation failed: %w", revokeErr)
	}
	return nil
}

// VerifyContactCredential verifies the account's primary contact credential.
func (s *accountServiceImpl) VerifyContactCredential(ctx context.Context, accountID string) error {
	// 0. Ensure account is active
	if _, err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}

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

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateCredential(ctx, tx, credential)
	})
	if err != nil {
		return err
	}

	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionCredentialVerify,
		audit.IPFromContext(ctx),
		utility.StringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "credential_type": credential.Type}),
		auditMetaFromContext(ctx),
	))

	return nil
}

// VerifyCredential is kept for compatibility with older internal callers.
//
// Deprecated: use VerifyContactCredential.
func (s *accountServiceImpl) VerifyCredential(ctx context.Context, accountID string) error {
	return s.VerifyContactCredential(ctx, accountID)
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
		// Password was already changed successfully, but caller should know session revocation failed
		// so they can take additional action (e.g., notify the user).
		return fmt.Errorf("password changed but session revocation failed: %w", revokeErr)
	}

	// 8. Audit log (sync — critical security event)
	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionPasswordChange,
		audit.IPFromContext(ctx),
		utility.StringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))

	return nil
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
		return fmt.Errorf("suspend succeeded but session revocation failed: %w", revokeErr)
	}

	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountSuspend,
		audit.IPFromContext(ctx),
		utility.StringPtr(accountID),
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

	s.auditLogSync(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountActivate,
		audit.IPFromContext(ctx),
		utility.StringPtr(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		auditMetaFromContext(ctx),
	))
	return nil
}

// ListAccounts returns a paginated list of accounts.
func (s *accountServiceImpl) ListAccounts(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error) {
	return s.accountRepo.FindAll(ctx, page, pageSize, status)
}

// GetAccountRoles returns the roles assigned to the account.
func (s *accountServiceImpl) GetAccountRoles(ctx context.Context, accountID string) ([]*domain.Role, error) {
	return s.roleRepo.FindRolesByAccountID(ctx, accountID)
}
