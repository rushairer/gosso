package oidc

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// OIDCModule holds all initialized OIDC services.
type OIDCModule struct {
	IDTokenService   *oidcService.IDTokenService
	DiscoveryService *oidcService.DiscoveryService
	JWKSService      *oidcService.JWKSService
	UserInfoService  *oidcService.UserInfoService
	LogoutService    *oidcService.LogoutService
}

// InitializeOIDCModule initializes the OIDC module
func InitializeOIDCModule(
	tokenSvc *tokenService.TokenService,
	accountSvc accountService.AccountService,
	authConfig config.AuthConfig,
	sessionSvc *sessionService.SessionService,
	credentialRepo accountRepo.CredentialRepository,
	clientRepo oauth2Repo.OAuth2ClientRepository,
	httpClient *http.Client,
	logger *zap.Logger,
) *OIDCModule {
	idTokenSvc := oidcService.NewIDTokenService(tokenSvc, authConfig.Issuer, accountSvc, credentialRepo, authConfig.IDTokenExpiry, logger)
	discoverySvc := oidcService.NewDiscoveryService(authConfig.Issuer)
	jwksSvc := oidcService.NewJWKSService(tokenSvc.KeyService())
	userInfoSvc := oidcService.NewUserInfoService(accountSvc, credentialRepo, logger)
	logoutSvc := oidcService.NewLogoutService(tokenSvc, sessionSvc, jwksSvc, authConfig.Issuer, clientRepo, httpClient, logger)

	return &OIDCModule{
		IDTokenService:   idTokenSvc,
		DiscoveryService: discoverySvc,
		JWKSService:      jwksSvc,
		UserInfoService:  userInfoSvc,
		LogoutService:    logoutSvc,
	}
}
