package service

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/rushairer/gosso/config"
	"go.uber.org/zap"
)

// EmailService 邮件发送服务
type EmailService struct {
	host     string
	port     int
	username string
	password string
	from     string
	logger   *zap.Logger
}

// NewEmailService 创建邮件服务实例
func NewEmailService(cfg config.SMTPConfig, logger *zap.Logger) *EmailService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &EmailService{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: cfg.Password,
		from:     cfg.From,
		logger:   logger,
	}
}

// SendVerificationCode 发送验证码邮件
func (s *EmailService) SendVerificationCode(ctx context.Context, to, code string) error {
	subject := "Your Verification Code"
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<p>Hello,</p>
<p>Your verification code is:</p>
<h2 style="font-size:32px;letter-spacing:8px;text-align:center;padding:20px;background:#f4f4f4;border-radius:8px;">%s</h2>
<p>This code expires in 10 minutes.</p>
<p>If you did not request this, please ignore this email.</p>
</body>
</html>`, code)

	msg := s.buildMessage(to, subject, body)
	return s.send(to, msg)
}

// SendPasswordResetLink 发送密码重置邮件
func (s *EmailService) SendPasswordResetLink(ctx context.Context, to, resetLink string) error {
	subject := "Reset Your Password"
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<p>Hello,</p>
<p>You requested to reset your password. Click the link below:</p>
<p><a href="%s" style="display:inline-block;padding:12px 24px;background:#007bff;color:#fff;text-decoration:none;border-radius:6px;">Reset Password</a></p>
<p>This link expires in 30 minutes.</p>
<p>If you did not request this, please ignore this email. Your password will remain unchanged.</p>
</body>
</html>`, resetLink)

	msg := s.buildMessage(to, subject, body)
	return s.send(to, msg)
}

func (s *EmailService) buildMessage(to, subject, body string) string {
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", s.from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return msg.String()
}

func (s *EmailService) send(to, msg string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	err := smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
	if err != nil {
		s.logger.Error("Failed to send email",
			zap.String("to", to),
			zap.Error(err))
		return fmt.Errorf("send email: %w", err)
	}

	s.logger.Info("Email sent", zap.String("to", to))
	return nil
}
