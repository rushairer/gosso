package account

import (
	"context"
	"gosso/internal/common/repository/account"
	"log"

	"gorm.io/gorm"
)

type AccountService struct {
	emailRepository account.EmailRepository
	phoneRepository account.PhoneRepository
}

func NewAccountService(db *gorm.DB) *AccountService {
	return &AccountService{
		emailRepository: account.NewEmailMySQLRepository(db),
		phoneRepository: account.NewPhoneMySQLRepository(db),
	}
}

func (c *AccountService) EmailRegister(ctx context.Context, address string) (err error) {
	email, created, err := c.emailRepository.FindOrCreate(ctx, address)
	log.Println(email, created, err)

	return
}

func (c *AccountService) PhoneRegister(ctx context.Context, number string) (err error) {
	phone, created, err := c.phoneRepository.FindOrCreate(ctx, number)
	log.Println(phone, created, err)
	return
}
