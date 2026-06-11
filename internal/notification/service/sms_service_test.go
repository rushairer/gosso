package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestStubSMSService_SendVerificationCode_ReturnsNotImplemented(t *testing.T) {
	svc := NewStubSMSService(zap.NewNop())
	err := svc.SendVerificationCode(context.Background(), "+1234567890", "123456")
	assert.ErrorIs(t, err, ErrSMSNotImplemented)
}
