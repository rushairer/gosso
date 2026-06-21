// Package service provides notification services (email, SMS).
//
// NOTE: SMS functionality is currently a stub implementation.
// All SMS verification code requests will return ErrSMSNotImplemented.
// To enable SMS support:
//  1. Add SMS gateway config to config package (e.g., config.SMSConfig)
//  2. Create a real SMSService implementation using the gateway SDK
//  3. Replace StubSMSService with the real implementation in the notification module wiring
package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

// SMSService SMS sending service interface
type SMSService interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
}

// ErrSMSNotImplemented is returned when SMS verification is attempted without a real SMS gateway.
var ErrSMSNotImplemented = errors.New("SMS verification is not yet supported, please use email verification")

// StubSMSService is a no-op placeholder that always returns ErrSMSNotImplemented.
// Replace with a real gateway implementation when SMS support is needed.
// See package-level docs for implementation guidance.
type StubSMSService struct {
	logger *zap.Logger
}

// NewStubSMSService creates a stub SMS service
func NewStubSMSService(logger *zap.Logger) *StubSMSService {
	logger = utility.EnsureLogger(logger)
	return &StubSMSService{logger: logger}
}

func (s *StubSMSService) SendVerificationCode(ctx context.Context, phone, code string) error {
	s.logger.Warn("SMS service not implemented, cannot send verification code",
		zap.String("phone", utility.MaskPhone(phone)))
	return fmt.Errorf("%w", ErrSMSNotImplemented)
}
