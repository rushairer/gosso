package account

import (
	"context"
	"log"
)

type SendPhoneCodeTask struct {
	number string
}

func NewSendPhoneCodeTask(number string) *SendPhoneCodeTask {
	return &SendPhoneCodeTask{number: number}
}

func (a *SendPhoneCodeTask) Run(ctx context.Context) error {
	log.Printf("send phone code to %s", a.number)
	// TODO: 发送手机号验证码
	return nil
}
