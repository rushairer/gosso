package oauth2

import (
	"database/sql"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/oauth2/service"
)

// InitializeOAuth2Module initializes the OAuth2 module
func InitializeOAuth2Module(
	db *sql.DB,
	redis *cache.RedisClient,
	logger *zap.Logger,
	authConfig config.AuthConfig,
) (
	service.OAuth2ClientService,
	*service.AuthCodeService,
	*service.ConsentService,
	*service.DeviceCodeService,
	repository.OAuth2ClientRepository,
) {
	clientRepo := repository.NewOAuth2ClientRepository(db)
	clientSvc := service.NewOAuth2ClientService(db, clientRepo)
	authCodeSvc := service.NewAuthCodeService(redis, logger, authConfig.AuthorizationCodeExpiry)
	consentSvc := service.NewConsentService(redis, logger)
	deviceCodeSvc := service.NewDeviceCodeService(redis, logger, authConfig.DeviceCodeExpiry, authConfig.DeviceCodeInterval)

	return clientSvc, authCodeSvc, consentSvc, deviceCodeSvc, clientRepo
}
