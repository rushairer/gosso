package email

import (
	"testing"
)

func TestEmailService_SendVerificationCode(t *testing.T) {
	// 测试邮件服务的验证码发送功能
	emailService := NewEmailService(
		"localhost",           // host
		1025,                  // port
		"",                    // username (Mailpit 不需要认证)
		"",                    // password (Mailpit 不需要认证)
		"noreply@gosso.local", // from
	)

	// 测试发送验证码邮件
	err := emailService.SendVerificationCode("test@example.com", "123456")
	if err != nil {
		t.Errorf("SendVerificationCode failed: %v", err)
	}
}

// TestEmailService_NewEmailService 测试邮件服务的创建
func TestEmailService_NewEmailService(t *testing.T) {
	emailService := NewEmailService(
		"smtp.example.com",
		587,
		"user@example.com",
		"password",
		"noreply@example.com",
	)

	if emailService == nil {
		t.Error("NewEmailService returned nil")
		return
	}

	if emailService.host != "smtp.example.com" {
		t.Errorf("Expected host 'smtp.example.com', got '%s'", emailService.host)
	}

	if emailService.port != 587 {
		t.Errorf("Expected port 587, got %d", emailService.port)
	}

	if emailService.username != "user@example.com" {
		t.Errorf("Expected username 'user@example.com', got '%s'", emailService.username)
	}

	if emailService.password != "password" {
		t.Errorf("Expected password 'password', got '%s'", emailService.password)
	}

	if emailService.from != "noreply@example.com" {
		t.Errorf("Expected from 'noreply@example.com', got '%s'", emailService.from)
	}
}
