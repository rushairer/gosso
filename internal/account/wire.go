package account

import (
	"database/sql"

	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/account/service"
)

// InitializeAccountModule 初始化账号模块（依赖注入）
func InitializeAccountModule(db *sql.DB) service.AccountService {
	// 创建 Repository 实例
	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	// 创建 Service 实例
	accountService := service.NewAccountService(
		db,
		accountRepo,
		credentialRepo,
		federatedIdentityRepo,
		roleRepo,
	)

	return accountService
}
