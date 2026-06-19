package oauth2

import (
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/cache"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/oauth2/service"
)

// OAuth2Module holds all initialized OAuth2 services and repositories.
type OAuth2Module struct {
	ClientService     service.OAuth2ClientService
	AuthCodeService   *service.AuthCodeService
	ConsentService    *service.ConsentService
	DeviceCodeService *service.DeviceCodeService
	ClientRepo        repository.OAuth2ClientRepository
}

// InitializeOAuth2Module initializes the OAuth2 module
func InitializeOAuth2Module(
	db *sql.DB,
	redis *cache.RedisClient,
	logger *zap.Logger,
	authConfig config.AuthConfig,
	auditor *auditService.Auditor,
) (*OAuth2Module, error) {
	clientRepo := repository.NewOAuth2ClientRepository(db)
	consentRepo := repository.NewConsentRepository(db)
	clientSvc := service.NewOAuth2ClientService(db, clientRepo, auditor, logger)
	authCodeSvc, err := service.NewAuthCodeService(redis, logger, authConfig.AuthorizationCodeExpiry)
	if err != nil {
		return nil, fmt.Errorf("initialize auth code service: %w", err)
	}
	consentSvc := service.NewConsentService(db, consentRepo, redis, logger)
	deviceCodeSvc := service.NewDeviceCodeService(redis, logger, authConfig.DeviceCodeExpiry, authConfig.DeviceCodeInterval)

	return &OAuth2Module{
		ClientService:     clientSvc,
		AuthCodeService:   authCodeSvc,
		ConsentService:    consentSvc,
		DeviceCodeService: deviceCodeSvc,
		ClientRepo:        clientRepo,
	}, nil
}
