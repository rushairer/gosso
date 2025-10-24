package account_test

import (
	"context"
	"errors"
	"gosso/internal/common/domain/account"
	accountRepository "gosso/internal/common/repository/account"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"
	"gorm.io/gorm"
)

func TestSpecAccountEmail(t *testing.T) {
	Convey("创建一个邮箱帐号", t, func() {
		address := "test@example.com"
		target := gorm.G[account.Email](nil)
		emailRepository := accountRepository.NewEmailMySQLRepository(nil)
		Convey("当首次创建成功时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.Email,
				) error {
					r.Address = address
					now := time.Now()
					r.CreatedAt = now
					r.UpdatedAt = now
					return nil
				})
			defer patches.Reset()
			email, created, err := emailRepository.FindOrCreate(context.Background(), address)
			So(err, ShouldBeNil)
			So(created, ShouldBeTrue)
			So(email.Address, ShouldEqual, address)
		})
		Convey("当创建失败时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.Email,
				) error {
					r.Address = address
					return errors.New("create failed")
				})
			defer patches.Reset()
			email, created, err := emailRepository.FindOrCreate(context.Background(), address)
			So(err, ShouldNotBeNil)
			So(created, ShouldBeFalse)
			So(email.Address, ShouldEqual, address)
		})
		Convey("当邮箱已存在时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.Email,
				) error {
					r.Address = address
					now := time.Now()
					r.CreatedAt = now
					r.UpdatedAt = now.Add(time.Hour)
					return nil
				})
			defer patches.Reset()
			email, created, err := emailRepository.FindOrCreate(context.Background(), address)
			So(err, ShouldBeNil)
			So(created, ShouldBeFalse)
			So(email.Address, ShouldEqual, address)
		})
	})
}
