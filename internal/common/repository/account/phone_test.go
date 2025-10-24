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

func TestSpecAccountPhone(t *testing.T) {
	Convey("创建一个手机号帐号", t, func() {
		number := "13800000000"
		target := gorm.G[account.Phone](nil)
		phoneRepository := accountRepository.NewPhoneMySQLRepository(nil)
		Convey("当首次创建成功时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.Phone,
				) error {
					r.Number = number
					now := time.Now()
					r.CreatedAt = now
					r.UpdatedAt = now
					return nil
				})
			defer patches.Reset()
			phone, created, err := phoneRepository.FindOrCreate(context.Background(), number)
			So(err, ShouldBeNil)
			So(created, ShouldBeTrue)
			So(phone.Number, ShouldEqual, number)
		})
		Convey("当创建失败时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.Phone,
				) error {
					r.Number = number
					return errors.New("create failed")
				})
			defer patches.Reset()
			phone, created, err := phoneRepository.FindOrCreate(context.Background(), number)
			So(err, ShouldNotBeNil)
			So(created, ShouldBeFalse)
			So(phone.Number, ShouldEqual, number)
		})
		Convey("当手机号已存在时", func() {
			patches := gomonkey.ApplyMethodFunc(
				target,
				"Create",
				func(
					ctx context.Context,
					r *account.Phone,
				) error {
					r.Number = number
					now := time.Now()
					r.CreatedAt = now
					r.UpdatedAt = now.Add(time.Hour)
					return nil
				})
			defer patches.Reset()
			phone, created, err := phoneRepository.FindOrCreate(context.Background(), number)
			So(err, ShouldBeNil)
			So(created, ShouldBeFalse)
			So(phone.Number, ShouldEqual, number)
		})
	})
}
