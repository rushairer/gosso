package account

import (
	"context"
	"log"
)

type SendEmailCodeTask struct {
	address string
}

func NewSendEmailCodeTask(address string) *SendEmailCodeTask {
	return &SendEmailCodeTask{address: address}
}

func (a *SendEmailCodeTask) Run(ctx context.Context) error {
	log.Printf("send email code to %s", a.address)
	// TODO: 发送邮箱验证码
	return nil
}
