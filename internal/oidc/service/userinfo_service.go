package service

import (
	"context"
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

	// Pre-fetch email and phone credentials in a single DB round-trip
	// if both scopes are requested.
	needEmail, needPhone := false, false
	for _, scope := range scopes {
		switch scope {
		case "email":
			needEmail = true
		case "phone":
			needPhone = true
		}
	}

	var credsByType map[accountDomain.CredentialType][]*accountDomain.Credential
	if needEmail || needPhone {
		var credTypes []accountDomain.CredentialType
		if needEmail {
			credTypes = append(credTypes, accountDomain.CredentialTypeEmail)
		}
		if needPhone {
			credTypes = append(credTypes, accountDomain.CredentialTypePhone)
		}
		creds, err := s.credentialRepo.FindByAccountAndTypes(ctx, accountID, credTypes...)
		if err != nil {
			return nil, fmt.Errorf("find credentials: %w", err)
		}
		credsByType = make(map[accountDomain.CredentialType][]*accountDomain.Credential, len(credTypes))
		for _, cred := range creds {
			credsByType[cred.Type] = append(credsByType[cred.Type], cred)
		}
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
			s.addEmailInfo(credsByType[accountDomain.CredentialTypeEmail], info)
		case "phone":
			s.addPhoneInfo(credsByType[accountDomain.CredentialTypePhone], info)
		}
	}

	return info, nil
}

func (s *UserInfoService) addEmailInfo(creds []*accountDomain.Credential, info map[string]any) {
	if len(creds) > 0 && creds[0].Identifier != nil {
		info["email"] = *creds[0].Identifier
		info["email_verified"] = creds[0].IsVerified()
	}
}

func (s *UserInfoService) addPhoneInfo(creds []*accountDomain.Credential, info map[string]any) {
	if len(creds) > 0 && creds[0].Identifier != nil {
		info["phone_number"] = *creds[0].Identifier
		info["phone_number_verified"] = creds[0].IsVerified()
	}
}
