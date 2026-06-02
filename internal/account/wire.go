package account

import (
	"database/sql"

	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/account/service"
	auditService "github.com/rushairer/gosso/internal/audit/service"
)

// InitializeAccountModule initializes the account module (dependency injection)
func InitializeAccountModule(db *sql.DB, auditor *auditService.Auditor) service.AccountService {
	// Create Repository instances
	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	// Create Service instances
	accountService := service.NewAccountService(
		db,
		accountRepo,
		credentialRepo,
		federatedIdentityRepo,
		roleRepo,
		auditor,
	)

	return accountService
}
