package service

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	authService "github.com/rushairer/gosso/internal/auth/service"
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
		return nil, authService.ErrAccountNotActive
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
			s.addEmailInfo(ctx, accountID, info)
		case "phone":
			s.addPhoneInfo(ctx, accountID, info)
		}
	}

	return info, nil
}

func (s *UserInfoService) addEmailInfo(ctx context.Context, accountID string, info map[string]any) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeEmail)
	if err != nil {
		s.logger.Warn("Failed to query email credentials for userinfo", zap.String("account_id", accountID), zap.Error(err))
		return
	}
	if len(creds) > 0 && creds[0].Identifier != nil {
		info["email"] = *creds[0].Identifier
		info["email_verified"] = creds[0].IsVerified()
	}
}

func (s *UserInfoService) addPhoneInfo(ctx context.Context, accountID string, info map[string]any) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypePhone)
	if err != nil {
		s.logger.Warn("Failed to query phone credentials for userinfo", zap.String("account_id", accountID), zap.Error(err))
		return
	}
	if len(creds) > 0 && creds[0].Identifier != nil {
		info["phone_number"] = *creds[0].Identifier
		info["phone_number_verified"] = creds[0].IsVerified()
	}
}
