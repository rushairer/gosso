package service

import (
	"context"
	"fmt"
)

// SMSService 短信发送服务接口
type SMSService interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
}

// StubSMSService 短信服务桩实现（生产环境替换为实际 SMS 网关）
type StubSMSService struct{}

// NewStubSMSService 创建 SMS 桩服务
func NewStubSMSService() *StubSMSService {
	return &StubSMSService{}
}

func (s *StubSMSService) SendVerificationCode(ctx context.Context, phone, code string) error {
	return fmt.Errorf("SMS service not implemented")
}
