package oidc

import (
	"database/sql"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// InitializeOIDCModule initializes the OIDC module
func InitializeOIDCModule(
	db *sql.DB,
	tokenSvc *tokenService.TokenService,
	accountSvc accountService.AccountService,
	authConfig config.AuthConfig,
	logger *zap.Logger,
) (*oidcService.IDTokenService, *oidcService.DiscoveryService, *oidcService.JWKSService, *oidcService.UserInfoService) {
	credentialRepo := accountRepo.NewCredentialRepository(db)

	idTokenSvc := oidcService.NewIDTokenService(tokenSvc, authConfig.Issuer, accountSvc, credentialRepo, logger)
	discoverySvc := oidcService.NewDiscoveryService(authConfig.Issuer)
	jwksSvc := oidcService.NewJWKSService(tokenSvc.KeyService())
	userInfoSvc := oidcService.NewUserInfoService(accountSvc, credentialRepo, logger)

	return idTokenSvc, discoverySvc, jwksSvc, userInfoSvc
}
