package service

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"time"

	"go.uber.org/zap"
	"gopkg.in/gomail.v2"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/utility"
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
// Note: gomail v2 does not support context.Context. The send method uses a dedicated
// 30-second SMTP timeout to bound operation duration. The underlying goroutine may
// complete independently after the caller returns on timeout or context cancellation.
func NewEmailService(cfg config.SMTPConfig, logger *zap.Logger) *EmailService {
	logger = utility.EnsureLogger(logger)
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
	msg := gomail.NewMessage()
	msg.SetHeader("From", s.from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", htmlBody)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.dialer.DialAndSend(msg)
	}()

	// Use a dedicated SMTP timeout to bound the overall operation duration,
	// since gomail does not support context propagation to the underlying TCP connection.
	const smtpTimeout = 30 * time.Second

	select {
	case err := <-errCh:
		if err != nil {
			s.logger.Error("Failed to send email",
				zap.String("to", maskEmail(to)),
				zap.Error(err))
			return fmt.Errorf("send email: %w", err)
		}
	case <-time.After(smtpTimeout):
		s.logger.Warn("Email send timed out; SMTP goroutine will complete independently",
			zap.String("to", maskEmail(to)),
			zap.Duration("timeout", smtpTimeout))
		return fmt.Errorf("send email: SMTP timeout after %s", smtpTimeout)
	case <-ctx.Done():
		s.logger.Warn("Email send interrupted by context; SMTP goroutine will complete independently",
			zap.String("to", maskEmail(to)),
			zap.Error(ctx.Err()))
		return fmt.Errorf("send email: %w", ctx.Err())
	}

	s.logger.Info("Email sent", zap.String("to", maskEmail(to)))
	return nil
}

// maskEmail masks PII in email addresses (e.g., "user@example.com" -> "u***@e***.com")
func maskEmail(email string) string {
	return utility.MaskEmail(email)
}
