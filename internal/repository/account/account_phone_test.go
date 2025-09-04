package account_test

import (
	"context"
	"errors"
	"gosso/internal/domain/account"
	accountRepository "gosso/internal/repository/account"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
	"gorm.io/gorm"
)

func TestSpecAccountPhone(t *testing.T) {
	Convey("创建一个手机号帐号", t, func() {
		phoneString := "13800000000"
		target := gorm.G[account.AccountPhone](nil)
		accountPhoneRepository := accountRepository.NewAccountPhoneMySQLRepository(nil)
		Convey("当首次创建成功时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.AccountPhone,
				) error {
					r.Phone = phoneString
					now := time.Now()
					r.CreatedAt = now
					r.UpdatedAt = now
					return nil
				})
			defer patches.Reset()
			accountPhone, created, err := accountPhoneRepository.FindOrCreate(context.Background(), phoneString)
			So(err, ShouldBeNil)
			So(created, ShouldBeTrue)
			So(accountPhone.Phone, ShouldEqual, phoneString)
		})
		Convey("当创建失败时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.AccountPhone,
				) error {
					r.Phone = phoneString
					return errors.New("create failed")
				})
			defer patches.Reset()
			accountPhone, created, err := accountPhoneRepository.FindOrCreate(context.Background(), phoneString)
			So(err, ShouldNotBeNil)
			So(created, ShouldBeFalse)
			So(accountPhone.Phone, ShouldEqual, phoneString)
		})
		Convey("当邮箱已存在时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.AccountPhone,
				) error {
					r.Phone = phoneString
					now := time.Now()
					r.CreatedAt = now
					r.UpdatedAt = now.Add(time.Hour)
					return nil
				})
			defer patches.Reset()
			accountPhone, created, err := accountPhoneRepository.FindOrCreate(context.Background(), phoneString)
			So(err, ShouldBeNil)
			So(created, ShouldBeFalse)
			So(accountPhone.Phone, ShouldEqual, phoneString)
		})
	})
}
