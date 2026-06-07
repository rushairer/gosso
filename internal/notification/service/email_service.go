package service

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"time"

	"github.com/wneessen/go-mail"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/utility"
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
	client *mail.Client
	from   string
	logger *zap.Logger
}

// NewEmailService creates a new email service instance.
func NewEmailService(cfg config.SMTPConfig, logger *zap.Logger) *EmailService {
	logger = utility.EnsureLogger(logger)

	opts := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithTLSPolicy(mail.TLSOpportunistic),
		mail.WithTimeout(30 * time.Second),
	}
	if cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(cfg.Username),
			mail.WithPassword(cfg.Password),
		)
	}

	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		logger.Error("Failed to create mail client, email sending will fail",
			zap.String("host", cfg.Host), zap.Error(err))
	}

	return &EmailService{
		client: client,
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

	return s.send(ctx, to, subject, body.String())
}

// SendPasswordResetLink sends a password reset email
func (s *EmailService) SendPasswordResetLink(ctx context.Context, to, resetLink string) error {
	subject := "Reset Your Password"
	var body bytes.Buffer
	if err := passwordResetTmpl.Execute(&body, struct{ ResetLink string }{ResetLink: resetLink}); err != nil {
		return fmt.Errorf("render password reset template: %w", err)
	}

	return s.send(ctx, to, subject, body.String())
}

func (s *EmailService) send(ctx context.Context, to, subject, htmlBody string) error {
	if s.client == nil {
		return fmt.Errorf("send email: mail client not initialized")
	}

	msg := mail.NewMsg()
	if err := msg.From(s.from); err != nil {
		return fmt.Errorf("set from address: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("set to address: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, htmlBody)

	if err := s.client.DialAndSendWithContext(ctx, msg); err != nil {
		s.logger.Error("Failed to send email",
			zap.String("to", maskEmail(to)),
			zap.Error(err))
		return fmt.Errorf("send email: %w", err)
	}

	s.logger.Info("Email sent", zap.String("to", maskEmail(to)))
	return nil
}

// maskEmail masks PII in email addresses
func maskEmail(email string) string {
	return utility.MaskEmail(email)
}
