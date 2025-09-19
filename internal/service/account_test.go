package service_test

import (
	"context"
	"gosso/internal/service"
	"gosso/utility"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func NewTestAccountService() *service.AccountService {
	db := utility.NewTestDB()
	return service.NewAccountService(db)
}

func TestAccountService_EmailRegister(t *testing.T) {
	accountService := NewTestAccountService()
	ctx := context.Background()

	Convey("注册邮箱帐号", t, func() {
		err := accountService.EmailRegister(ctx, "test@example.com")

		So(err, ShouldBeNil)
	})
}

func TestAccountService_PhoneRegister(t *testing.T) {
	accountService := NewTestAccountService()
	ctx := context.Background()

	Convey("注册手机号码", t, func() {
		err := accountService.PhoneRegister(ctx, "12345678901")

		So(err, ShouldBeNil)
	})
}
