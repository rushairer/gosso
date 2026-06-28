package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	"github.com/google/uuid"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/utility"
)

// UpdateProfile updates the display name for a user.
func (s *AuthService) UpdateProfile(ctx context.Context, accountID string, displayName string) (*accountDomain.Account, error) {
	if accountID == "" {
		return nil, fmt.Errorf("account id is required")
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return nil, fmt.Errorf("display name is required")
	}

	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	account.DisplayName = displayName

	if err := s.accountSvc.UpdateAccount(ctx, account); err != nil {
		return nil, err
	}

	var acctID *string
	if accountID != "" {
		acctID = &accountID
	}
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountUpdate,
		accountID,
		acctID,
		utility.MarshalJSONOrEmpty(map[string]any{"display_name": displayName}),
		utility.MarshalJSONOrEmpty(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return account, nil
}

// UpdateEmail updates the email credential for a user.
func (s *AuthService) UpdateEmail(ctx context.Context, accountID string, newEmail string) error {
	if accountID == "" {
		return fmt.Errorf("account id is required")
	}
	newEmail = strings.ToLower(strings.TrimSpace(newEmail))
	if newEmail == "" {
		return fmt.Errorf("email is required")
	}

	// Run in transaction to prevent TOCTOU race conditions
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// 1. Check if email is already in use by another active account
		existing, err := s.credentialRepo.FindByTypeAndIdentifierTx(ctx, tx, accountDomain.CredentialTypeEmail, newEmail)
		if err == nil && existing != nil {
			if existing.AccountID != accountID {
				return ErrEmailAlreadyInUse
			}
		} else if err != nil && !errors.Is(err, accountRepo.ErrCredentialNotFound) {
			return err
		}

		// 2. Find the user's existing email credential
		creds, err := s.credentialRepo.FindByAccountAndTypeTx(ctx, tx, accountID, accountDomain.CredentialTypeEmail)
		if err != nil {
			return err
		}

		now := time.Now()
		var emailCred *accountDomain.Credential
		if len(creds) > 0 {
			emailCred = creds[0]
			emailCred.Identifier = &newEmail
			emailCred.Verified = true
			emailCred.VerifiedAt = &now
			emailCred.UpdatedAt = now
			if err := s.credentialRepo.UpdateCredential(ctx, tx, emailCred); err != nil {
				return err
			}
		} else {
			// If for some reason they don't have an email credential, create one
			isPrimary := true
			emailCred = &accountDomain.Credential{
				ID:                uuid.New().String(),
				AccountID:         accountID,
				Type:              accountDomain.CredentialTypeEmail,
				Identifier:        &newEmail,
				Verified:          true,
				VerifiedAt:        &now,
				PrimaryCredential: isPrimary,
				CreatedAt:         now,
				UpdatedAt:         now,
			}
			if err := s.credentialRepo.CreateCredentials(ctx, tx, []*accountDomain.Credential{emailCred}); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	// 3. Log audit event
	var acctID *string
	if accountID != "" {
		acctID = &accountID
	}
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountUpdate,
		accountID,
		acctID,
		utility.MarshalJSONOrEmpty(map[string]any{"email": newEmail}),
		utility.MarshalJSONOrEmpty(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return nil
}

// IsEmailAvailable checks whether the given email address is available for use.
func (s *AuthService) IsEmailAvailable(ctx context.Context, email string) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false, fmt.Errorf("email is required")
	}

	_, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, accountDomain.CredentialTypeEmail, email)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, accountRepo.ErrCredentialNotFound) {
		return true, nil
	}
	return false, err
}
