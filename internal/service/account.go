package service

import (
	"context"
	"gosso/internal/repository/account"
	"log"

	"gorm.io/gorm"
)

type AccountService struct {
	accountEmailRepository account.AccountEmailRepository
	accountPhoneRepository account.AccountPhoneRepository
}

func NewAccountService(db *gorm.DB) *AccountService {
	return &AccountService{
		accountEmailRepository: account.NewAccountEmailMySQLRepository(db),
		accountPhoneRepository: account.NewAccountPhoneMySQLRepository(db),
	}
}

func (c *AccountService) EmailRegister(ctx context.Context, email string) (err error) {
	accountEmail, created, err := c.accountEmailRepository.FindOrCreate(ctx, email)
	log.Println(accountEmail, created, err)

	return
}

func (c *AccountService) PhoneRegister(ctx context.Context, phone string) (err error) {
	accountPhone, created, err := c.accountPhoneRepository.FindOrCreate(ctx, phone)
	log.Println(accountPhone, created, err)
	return
}
