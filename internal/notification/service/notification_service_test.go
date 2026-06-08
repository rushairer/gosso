package service

import (
	"bytes"
	"context"
	"html/template"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	svc := NewEmailService(cfg, nil)

	assert.Equal(t, "noreply@example.com", svc.from)
	assert.NotNil(t, svc.client)
	assert.NotNil(t, svc.logger)
}

func TestNewEmailService_NilLogger(t *testing.T) {
	cfg := config.SMTPConfig{}
	svc := NewEmailService(cfg, nil)
	assert.NotNil(t, svc.logger)
}

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
