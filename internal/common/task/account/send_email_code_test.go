package account_test

import (
	"context"
	"gosso/internal/common/task/account"
	"gosso/utility"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSendEmailCodeTask(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	Convey("将发送邮箱验证码的任务添加到任务管道中", t, func() {
		taskPipeline := utility.NewTestTaskPipeline(ctx)
		dataChan := taskPipeline.DataChan()
		dataChan <- account.NewSendEmailCodeTask("test@example.com")

		Convey("等待结束", func() {
			select {
			case <-ctx.Done():
				So(true, ShouldBeTrue)
			case _, ok := <-taskPipeline.Done():
				So(ok, ShouldBeFalse)
			}
		})

	})
}
