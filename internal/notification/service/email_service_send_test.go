package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/config"
)

// ──────────────────────────────────────────────
// maskEmail wrapper
// ──────────────────────────────────────────────

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard email", "user@example.com", "u***@e***"},
		{"short local", "a@b.com", "a***@b***"},
		{"empty", "", "***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, maskEmail(tt.input))
		})
	}
}

// ──────────────────────────────────────────────
// send: invalid "to" address
// ──────────────────────────────────────────────

func TestSend_InvalidTo(t *testing.T) {
	svc, err := NewEmailService(config.SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
	}, nil)
	require.NoError(t, err)

	err = svc.send(context.Background(), "", "Subject", "<p>body</p>")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set to address")
}

// ──────────────────────────────────────────────
// send: connection error (unreachable SMTP)
// ──────────────────────────────────────────────

func TestSend_ConnectionError(t *testing.T) {
	svc, err := NewEmailService(config.SMTPConfig{
		Host: "127.0.0.1",
		Port: 1, // unlikely to be listening
		From: "noreply@example.com",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, svc.client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = svc.send(ctx, "user@example.com", "Subject", "<p>body</p>")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "send email")
}

// ──────────────────────────────────────────────
// SendVerificationCode / SendPasswordResetLink via unreachable SMTP
// ──────────────────────────────────────────────

func TestSendVerificationCode_ConnectionError(t *testing.T) {
	svc, err := NewEmailService(config.SMTPConfig{
		Host: "127.0.0.1",
		Port: 1,
		From: "noreply@example.com",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, svc.client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = svc.SendVerificationCode(ctx, "user@example.com", "123456")
	assert.Error(t, err)
}

func TestSendPasswordResetLink_ConnectionError(t *testing.T) {
	svc, err := NewEmailService(config.SMTPConfig{
		Host: "127.0.0.1",
		Port: 1,
		From: "noreply@example.com",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, svc.client)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = svc.SendPasswordResetLink(ctx, "user@example.com", "https://example.com/reset")
	assert.Error(t, err)
}

// ──────────────────────────────────────────────
// NewEmailService without SMTP auth
// ──────────────────────────────────────────────

func TestNewEmailService_WithoutAuth(t *testing.T) {
	cfg := config.SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "noreply@example.com",
		// Username is empty → no SMTP auth
	}
	svc, err := NewEmailService(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, svc.client)
	assert.Equal(t, "noreply@example.com", svc.from)
}
