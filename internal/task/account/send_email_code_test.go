package account_test

import (
	"context"
	"gosso/internal/task/account"
	"gosso/utility"
	"testing"
	"time"
)

func TestSendEmailCodeTask(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	taskPipeline := utility.NewTestTaskPipeline(ctx)
	taskPipeline.Add(ctx, account.NewSendEmailCodeTask("test@example.com"))

	<-ctx.Done()
}
