package account_test

import (
	"context"
	"gosso/internal/task/account"
	"gosso/utility"
	"testing"
	"time"
)

func TestSendPhoneCodeTask(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	taskPipeline := utility.NewTestTaskPipeline(ctx)
	taskPipeline.Add(ctx, account.NewSendPhoneCodeTask("12345678901"))

	<-ctx.Done()
}
