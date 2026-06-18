package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/utility"
)

// UserInfoService OIDC UserInfo service
type UserInfoService struct {
	accountSvc     accountService.AccountService
	credentialRepo accountRepo.CredentialRepository
	logger         *zap.Logger
}

// NewUserInfoService creates a new instance of UserInfoService
func NewUserInfoService(
	accountSvc accountService.AccountService,
	credentialRepo accountRepo.CredentialRepository,
	logger *zap.Logger,
) *UserInfoService {
	logger = utility.EnsureLogger(logger)
	return &UserInfoService{
		accountSvc:     accountSvc,
		credentialRepo: credentialRepo,
		logger:         logger,
	}
}

// GetUserInfo returns user information based on scope
func (s *UserInfoService) GetUserInfo(ctx context.Context, accountID string, scopes []string) (map[string]any, error) {
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}

	if account.Status != accountDomain.AccountStatusActive {
		return nil, accountService.ErrAccountNotActive
	}

	info := map[string]any{
		"sub": accountID,
	}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			info["name"] = account.DisplayName
			if account.Username != nil {
				info["preferred_username"] = *account.Username
			}
			if account.AvatarURL != nil && *account.AvatarURL != "" {
				info["picture"] = *account.AvatarURL
			}
			info["locale"] = account.Locale
		case "email":
			if err := s.addEmailInfo(ctx, accountID, info); err != nil {
				return nil, err
			}
		case "phone":
			if err := s.addPhoneInfo(ctx, accountID, info); err != nil {
				return nil, err
			}
		}
	}

	return info, nil
}

func (s *UserInfoService) addEmailInfo(ctx context.Context, accountID string, info map[string]any) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeEmail)
	if err != nil {
		if errors.Is(err, accountRepo.ErrCredentialNotFound) {
			return nil // no email credential is not an error
		}
		return fmt.Errorf("find email credential: %w", err)
	}
	if len(creds) > 0 && creds[0].Identifier != nil {
		info["email"] = *creds[0].Identifier
		info["email_verified"] = creds[0].IsVerified()
	}
	return nil
}

func (s *UserInfoService) addPhoneInfo(ctx context.Context, accountID string, info map[string]any) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypePhone)
	if err != nil {
		if errors.Is(err, accountRepo.ErrCredentialNotFound) {
			return nil // no phone credential is not an error
		}
		return fmt.Errorf("find phone credential: %w", err)
	}
	if len(creds) > 0 && creds[0].Identifier != nil {
		info["phone_number"] = *creds[0].Identifier
		info["phone_number_verified"] = creds[0].IsVerified()
	}
	return nil
}
