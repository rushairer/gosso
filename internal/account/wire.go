package account

import (
	"database/sql"

	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/account/service"
	auditService "github.com/rushairer/gosso/internal/audit/service"
)

// AccountModule holds the account service and shared repositories.
type AccountModule struct {
	Service              service.AccountService
	AccountRepo          repository.AccountRepository
	CredentialRepo       repository.CredentialRepository
	FederatedIdentityRepo repository.FederatedIdentityRepository
	RoleRepo             repository.RoleRepository
}

// InitializeAccountModule initializes the account module (dependency injection)
func InitializeAccountModule(db *sql.DB, auditor *auditService.Auditor) *AccountModule {
	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := service.NewAccountService(
		db,
		accountRepo,
		credentialRepo,
		federatedIdentityRepo,
		roleRepo,
		auditor,
	)

	return &AccountModule{
		Service:              accountService,
		AccountRepo:          accountRepo,
		CredentialRepo:       credentialRepo,
		FederatedIdentityRepo: federatedIdentityRepo,
		RoleRepo:             roleRepo,
	}
}
