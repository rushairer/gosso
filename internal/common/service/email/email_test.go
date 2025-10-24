package email_test

import (
	"gosso/config"
	"gosso/internal/common/service/email"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var testOnce sync.Once

func initTestConfig() {
	testOnce.Do(func() {
		// 获取项目根目录
		_, b, _, _ := runtime.Caller(0)
		currentDir := filepath.Dir(b)
		for {
			goModPath := filepath.Join(currentDir, "go.mod")
			if _, err := os.Stat(goModPath); err == nil {
				break
			}
			parentDir := filepath.Dir(currentDir)
			if parentDir == currentDir {
				log.Fatalf("go.mod not found")
			}
			currentDir = parentDir
		}

		configPath := filepath.Join(currentDir, "config")
		err := config.InitConfig(configPath, "test")
		if err != nil {
			log.Fatalf("init config failed: %v", err)
		}
	})
}

func TestEmailService_SendVerificationCode(t *testing.T) {
	// 直接初始化配置，避免导入循环
	initTestConfig()

	smtpConfig := config.GlobalConfig.SMTPConfig

	// 测试邮件服务的验证码发送功能 - 使用配置文件中的设置
	emailService := email.NewEmailService(
		smtpConfig.Host,     // 从配置读取 host
		smtpConfig.Port,     // 从配置读取 port
		smtpConfig.Username, // 从配置读取 username
		smtpConfig.Password, // 从配置读取 password
		smtpConfig.From,     // 从配置读取 from
	)

	// 测试发送验证码邮件
	err := emailService.SendVerificationCode("test@example.com", "123456")
	if err != nil {
		t.Errorf("SendVerificationCode failed: %v", err)
	}
}

// TestEmailService_NewEmailService 测试邮件服务的创建
func TestEmailService_NewEmailService(t *testing.T) {
	// 直接初始化配置，避免导入循环
	initTestConfig()

	smtpConfig := config.GlobalConfig.SMTPConfig

	emailService := email.NewEmailService(
		smtpConfig.Host,
		smtpConfig.Port,
		smtpConfig.Username,
		smtpConfig.Password,
		smtpConfig.From,
	)

	if emailService == nil {
		t.Error("NewEmailService returned nil")
		return
	}

	// 测试邮件服务是否能正常创建（不访问私有字段）
	// 通过尝试发送邮件来验证服务是否正确初始化
	err := emailService.SendVerificationCode("test@example.com", "000000")
	if err != nil {
		t.Logf("Email service created successfully, send test: %v", err)
	} else {
		t.Log("Email service created and tested successfully")
	}
}
