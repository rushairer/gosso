package account_test

import (
	"context"
	"gosso/internal/task/account"
	"gosso/utility"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSendPhoneCodeTask(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()

	Convey("将发送手机验证码的任务添加到任务管道中", t, func() {
		taskPipeline := utility.NewTestTaskPipeline(ctx)
		err := taskPipeline.Add(ctx, account.NewSendPhoneCodeTask("12345678901"))
		So(err, ShouldBeNil)

		Convey("等待1秒后结束", func() {
			<-ctx.Done()
			So(true, ShouldBeTrue)
		})

	})
}
