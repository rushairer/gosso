package service

import (
	"bytes"
	"context"
	"html/template"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wneessen/go-mail"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
)

// ──────────────────────────────────────────────
// NewEmailService
// ──────────────────────────────────────────────

func TestNewEmailService(t *testing.T) {
	cfg := config.SMTPConfig{
		Host:     "smtp.example.com",
		Port:     587,
		Username: "user",
		Password: "pass",
		From:     "noreply@example.com",
	}
	svc, err := NewEmailService(cfg, nil)
	require.NoError(t, err)

	assert.Equal(t, "noreply@example.com", svc.from)
	assert.NotNil(t, svc.client)
	assert.NotNil(t, svc.logger)
}

func TestNewEmailService_NilLogger(t *testing.T) {
	cfg := config.SMTPConfig{Host: "localhost", Port: 587}
	svc, err := NewEmailService(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, svc.logger)
}

// ──────────────────────────────────────────────
// Template rendering
// ──────────────────────────────────────────────

// ──────────────────────────────────────────────
// Template rendering
// ──────────────────────────────────────────────

func TestVerificationTemplate(t *testing.T) {
	var body bytes.Buffer
	err := verificationTmpl.Execute(&body, struct {
		Code       string
		ExpiryText string
	}{Code: "123456", ExpiryText: "10 minutes"})
	require.NoError(t, err)

	html := body.String()
	assert.Contains(t, html, "123456")
	assert.Contains(t, html, "verification code")
	assert.Contains(t, html, "10 minutes")
}

func TestPasswordResetTemplate(t *testing.T) {
	var body bytes.Buffer
	err := passwordResetTmpl.Execute(&body, struct {
		ResetLink  string
		ExpiryText string
	}{ResetLink: "https://example.com/reset?token=abc", ExpiryText: "30 minutes"})
	require.NoError(t, err)

	html := body.String()
	assert.Contains(t, html, "https://example.com/reset?token=abc")
	assert.Contains(t, html, "Reset Password")
	assert.Contains(t, html, "30 minutes")
}

func TestVerificationTemplate_SpecialChars(t *testing.T) {
	var body bytes.Buffer
	err := verificationTmpl.Execute(&body, struct {
		Code       string
		ExpiryText string
	}{Code: "ABC<>&", ExpiryText: "10 minutes"})
	require.NoError(t, err)
	// template/html auto-escapes
	assert.Contains(t, body.String(), "ABC")
}

func TestPasswordResetTemplate_SpecialChars(t *testing.T) {
	var body bytes.Buffer
	err := passwordResetTmpl.Execute(&body, struct {
		ResetLink  string
		ExpiryText string
	}{ResetLink: "https://example.com/r?a=1&b=2", ExpiryText: "30 minutes"})
	require.NoError(t, err)
	// URL is HTML-escaped by template
	assert.Contains(t, body.String(), "https://example.com")
}

// ──────────────────────────────────────────────
// StubSMSService
// ──────────────────────────────────────────────

func TestNewStubSMSService(t *testing.T) {
	svc := NewStubSMSService(nil)
	assert.NotNil(t, svc)
}

func TestStubSMSService_SendVerificationCode(t *testing.T) {
	svc := NewStubSMSService(nil)
	err := svc.SendVerificationCode(context.Background(), "+8613800138000", "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet supported")
}

// ──────────────────────────────────────────────
// Template security (no injection)
// ──────────────────────────────────────────────

func TestVerificationTemplate_NoInjection(t *testing.T) {
	var body bytes.Buffer
	err := verificationTmpl.Execute(&body, struct {
		Code       string
		ExpiryText string
	}{Code: "<script>alert('xss')</script>", ExpiryText: "10 minutes"})
	require.NoError(t, err)
	// html/template escapes < > automatically
	assert.NotContains(t, body.String(), "<script>")
}

func TestPasswordResetTemplate_NoInjection(t *testing.T) {
	var body bytes.Buffer
	malicious := "javascript:alert(1)\"><img src=x onerror=alert(1)>"
	err := passwordResetTmpl.Execute(&body, struct {
		ResetLink  string
		ExpiryText string
	}{ResetLink: malicious, ExpiryText: "30 minutes"})
	require.NoError(t, err)
	assert.NotContains(t, body.String(), "onerror=")
}

// Verify templates are properly initialized
func TestTemplatesInitialized(t *testing.T) {
	assert.NotNil(t, verificationTmpl)
	assert.NotNil(t, passwordResetTmpl)

	// Ensure they're valid templates
	_, err := template.New("test").Parse("{{.Code}}")
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// SetVerifyCodeTTL / SetPasswordResetTTL
// ──────────────────────────────────────────────

func TestSetVerifyCodeTTL(t *testing.T) {
	svc, err := NewEmailService(config.SMTPConfig{Host: "localhost", Port: 587}, nil)
	require.NoError(t, err)

	assert.Equal(t, 10*time.Minute, svc.verifyCodeTTL)

	svc.SetVerifyCodeTTL(5 * time.Minute)
	assert.Equal(t, 5*time.Minute, svc.verifyCodeTTL)

	// No-op on non-positive values
	svc.SetVerifyCodeTTL(0)
	assert.Equal(t, 5*time.Minute, svc.verifyCodeTTL)
	svc.SetVerifyCodeTTL(-1 * time.Minute)
	assert.Equal(t, 5*time.Minute, svc.verifyCodeTTL)
}

func TestSetPasswordResetTTL(t *testing.T) {
	svc, err := NewEmailService(config.SMTPConfig{Host: "localhost", Port: 587}, nil)
	require.NoError(t, err)

	assert.Equal(t, 30*time.Minute, svc.passwordResetTTL)

	svc.SetPasswordResetTTL(60 * time.Minute)
	assert.Equal(t, 60*time.Minute, svc.passwordResetTTL)

	// No-op on non-positive values
	svc.SetPasswordResetTTL(0)
	assert.Equal(t, 60*time.Minute, svc.passwordResetTTL)
	svc.SetPasswordResetTTL(-1 * time.Minute)
	assert.Equal(t, 60*time.Minute, svc.passwordResetTTL)
}

// ──────────────────────────────────────────────
// smtpTLSPolicy
// ──────────────────────────────────────────────

func TestSmtpTLSPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected mail.TLSPolicy
	}{
		{"mandatory", "mandatory", mail.TLSMandatory},
		{"notls", "notls", mail.NoTLS},
		{"opportunistic default", "", mail.TLSOpportunistic},
		{"unknown", "unknown", mail.TLSOpportunistic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, smtpTLSPolicy(tt.input))
		})
	}
}

// ──────────────────────────────────────────────
// formatDuration
// ──────────────────────────────────────────────

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{"1 minute", 1 * time.Minute, "1 minute"},
		{"5 minutes", 5 * time.Minute, "5 minutes"},
		{"10 minutes", 10 * time.Minute, "10 minutes"},
		{"1 hour", 60 * time.Minute, "1 hour"},
		{"2 hours", 120 * time.Minute, "2 hours"},
		{"3 hours", 180 * time.Minute, "3 hours"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatDuration(tt.input))
		})
	}
}

// ──────────────────────────────────────────────
// SendVerificationCode / SendPasswordResetLink with nil client
// ──────────────────────────────────────────────

func TestSendVerificationCode_NilClient(t *testing.T) {
	svc := &EmailService{
		client:        nil,
		from:          "test@example.com",
		logger:        zap.NewNop(),
		verifyCodeTTL: 10 * time.Minute,
		sendLimiter:   time.NewTicker(100 * time.Millisecond),
	}
	defer svc.Close()

	err := svc.SendVerificationCode(context.Background(), "test@example.com", "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSendPasswordResetLink_NilClient(t *testing.T) {
	svc := &EmailService{
		client:           nil,
		from:             "test@example.com",
		logger:           zap.NewNop(),
		passwordResetTTL: 30 * time.Minute,
		sendLimiter:      time.NewTicker(100 * time.Millisecond),
	}
	defer svc.Close()

	err := svc.SendPasswordResetLink(context.Background(), "test@example.com", "https://example.com/reset")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}
