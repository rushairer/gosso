package task

import (
	"context"
	"log"
)

type AccountSendEmailCodeTask struct {
	email string
}

func NewAccountSendEmailCodeTask(email string) *AccountSendEmailCodeTask {
	return &AccountSendEmailCodeTask{email: email}
}

func (a *AccountSendEmailCodeTask) Run(ctx context.Context) error {
	log.Printf("send email code to %s", a.email)
	// TODO: 发送邮箱验证码
	return nil
}
