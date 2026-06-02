package service

import (
	"context"
	"fmt"
)

// SMSService SMS sending service interface
type SMSService interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
}

// StubSMSService stub implementation of the SMS service (replace with actual SMS gateway in production)
type StubSMSService struct{}

// NewStubSMSService creates a stub SMS service
func NewStubSMSService() *StubSMSService {
	return &StubSMSService{}
}

func (s *StubSMSService) SendVerificationCode(ctx context.Context, phone, code string) error {
	return fmt.Errorf("SMS service not implemented")
}
