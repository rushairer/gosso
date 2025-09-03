package service_test

import (
	"context"
	"gosso/internal/service"
	"gosso/utility"
	"testing"
)

func NewTestAccountService() *service.AccountService {
	db := utility.NewTestDB()
	return service.NewAccountService(db)
}

func TestAccountService_EmailRegister(t *testing.T) {
	accountService := NewTestAccountService()

	ctx := context.Background()

	err := accountService.EmailRegister(ctx, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccountService_PhoneRegister(t *testing.T) {
	accountService := NewTestAccountService()

	ctx := context.Background()

	err := accountService.PhoneRegister(ctx, "12345678901")
	if err != nil {
		t.Fatal(err)
	}
}
