package service

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/utility"
)

// SMSService SMS sending service interface
type SMSService interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
}

// StubSMSService stub implementation of the SMS service (replace with actual SMS gateway in production)
type StubSMSService struct {
	logger *zap.Logger
}

// NewStubSMSService creates a stub SMS service
func NewStubSMSService(logger *zap.Logger) *StubSMSService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &StubSMSService{logger: logger}
}

func (s *StubSMSService) SendVerificationCode(ctx context.Context, phone, code string) error {
	s.logger.Warn("SMS service not implemented, cannot send verification code",
		zap.String("phone", utility.MaskPhone(phone)))
	return fmt.Errorf("SMS verification is not yet supported, please use email verification")
}
