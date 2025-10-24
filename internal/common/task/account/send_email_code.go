package account

import (
	"context"
	"crypto/rand"
	"fmt"
	"gosso/config"
	"gosso/internal/common/service/email"
	"log"
	"math/big"
	"time"
)

type SendEmailCodeTask struct {
	address string
}

func NewSendEmailCodeTask(address string) *SendEmailCodeTask {
	return &SendEmailCodeTask{address: address}
}

func (a *SendEmailCodeTask) Run(ctx context.Context) error {
	log.Printf("send email code to %s", a.address)

	// 生成6位数验证码
	code := generateVerificationCode()

	// 创建邮件服务
	smtpConfig := config.GlobalConfig.SMTPConfig
	emailService := email.NewEmailService(
		smtpConfig.Host,
		smtpConfig.Port,
		smtpConfig.Username,
		smtpConfig.Password,
		smtpConfig.From,
	)

	// 发送验证码邮件
	if err := emailService.SendVerificationCode(a.address, code); err != nil {
		log.Printf("Failed to send verification code to %s: %v", a.address, err)
		return fmt.Errorf("发送验证码失败: %w", err)
	}

	log.Printf("Verification code sent successfully to %s", a.address)
	return nil
}

// generateVerificationCode 生成6位数验证码
func generateVerificationCode() string {
	// 使用加密安全的随机数生成器
	max := big.NewInt(900000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// 如果加密随机数生成失败，使用时间戳作为后备方案
		log.Printf("Failed to generate secure random number: %v", err)
		return fmt.Sprintf("%06d", 100000+(int(time.Now().UnixNano())%900000))
	}
	code := n.Int64() + 100000 // 生成100000-999999之间的数字
	return fmt.Sprintf("%06d", code)
}
