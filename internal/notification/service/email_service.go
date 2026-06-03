package service

import (
	"bytes"
	"context"
	"fmt"
	"html/template"

	"go.uber.org/zap"
	"gopkg.in/gomail.v2"

	"github.com/rushairer/gosso/config"
)

var (
	verificationTmpl = template.Must(template.New("verification").Parse(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<p>Hello,</p>
<p>Your verification code is:</p>
<h2 style="font-size:32px;letter-spacing:8px;text-align:center;padding:20px;background:#f4f4f4;border-radius:8px;">{{.Code}}</h2>
<p>This code expires in 10 minutes.</p>
<p>If you did not request this, please ignore this email.</p>
</body>
</html>`))

	passwordResetTmpl = template.Must(template.New("password_reset").Parse(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<p>Hello,</p>
<p>You requested to reset your password. Click the link below:</p>
<p><a href="{{.ResetLink}}" style="display:inline-block;padding:12px 24px;background:#007bff;color:#fff;text-decoration:none;border-radius:6px;">Reset Password</a></p>
<p>This link expires in 30 minutes.</p>
<p>If you did not request this, please ignore this email. Your password will remain unchanged.</p>
</body>
</html>`))
)

// EmailService email sending service
type EmailService struct {
	dialer *gomail.Dialer
	from   string
	logger *zap.Logger
}

// NewEmailService creates a new email service instance.
// Note: gomail v2 does not support context.Context or connection timeouts.
// The SMTP connection uses the OS-level TCP timeout. Consider upgrading to a
// context-aware mail library if goroutine leaks are observed under load.
func NewEmailService(cfg config.SMTPConfig, logger *zap.Logger) *EmailService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &EmailService{
		dialer: gomail.NewDialer(cfg.Host, cfg.Port, cfg.Username, cfg.Password),
		from:   cfg.From,
		logger: logger,
	}
}

// SendVerificationCode sends a verification code email
func (s *EmailService) SendVerificationCode(ctx context.Context, to, code string) error {
	subject := "Your Verification Code"
	var body bytes.Buffer
	if err := verificationTmpl.Execute(&body, struct{ Code string }{Code: code}); err != nil {
		return fmt.Errorf("render verification template: %w", err)
	}

	return s.send(to, subject, body.String())
}

// SendPasswordResetLink sends a password reset email
func (s *EmailService) SendPasswordResetLink(ctx context.Context, to, resetLink string) error {
	subject := "Reset Your Password"
	var body bytes.Buffer
	if err := passwordResetTmpl.Execute(&body, struct{ ResetLink string }{ResetLink: resetLink}); err != nil {
		return fmt.Errorf("render password reset template: %w", err)
	}

	return s.send(to, subject, body.String())
}

func (s *EmailService) send(to, subject, htmlBody string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", s.from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", htmlBody)

	if err := s.dialer.DialAndSend(msg); err != nil {
		s.logger.Error("Failed to send email",
			zap.String("to", maskEmail(to)),
			zap.Error(err))
		return fmt.Errorf("send email: %w", err)
	}

	s.logger.Info("Email sent", zap.String("to", maskEmail(to)))
	return nil
}

// maskEmail masks PII in email addresses (e.g., "user@example.com" -> "u***@e***.com")
func maskEmail(email string) string {
	atIdx := -1
	for i, c := range email {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx > 0 && atIdx < len(email)-1 {
		local := email[:atIdx]
		domain := email[atIdx+1:]
		maskedLocal := string(local[0]) + "***"
		dotIdx := -1
		for i, c := range domain {
			if c == '.' {
				dotIdx = i
				break
			}
		}
		var maskedDomain string
		if dotIdx > 0 {
			maskedDomain = string(domain[0]) + "***" + domain[dotIdx:]
		} else {
			maskedDomain = string(domain[0]) + "***"
		}
		return maskedLocal + "@" + maskedDomain
	}
	if len(email) > 1 {
		return string(email[0]) + "***"
	}
	return "***"
}
