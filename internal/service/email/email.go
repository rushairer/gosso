package email

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"strings"

	"gopkg.in/gomail.v2"
)

//go:embed templates/verification_code.html
var verificationCodeTemplate string

type EmailService struct {
	host     string
	port     int
	username string
	password string
	from     string
}

func NewEmailService(host string, port int, username, password, from string) *EmailService {
	return &EmailService{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

// SendVerificationCode 发送验证码邮件
func (s *EmailService) SendVerificationCode(to, code string) error {
	// 解析模板
	tmpl, err := template.New("verification_code").Parse(verificationCodeTemplate)
	if err != nil {
		log.Printf("Failed to parse email template: %v", err)
		return fmt.Errorf("解析邮件模板失败: %w", err)
	}

	// 渲染模板
	var body strings.Builder
	data := struct {
		Code string
	}{
		Code: code,
	}

	if err := tmpl.Execute(&body, data); err != nil {
		log.Printf("Failed to execute email template: %v", err)
		return fmt.Errorf("渲染邮件模板失败: %w", err)
	}

	// 创建邮件
	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "验证码 - GoSSO")
	m.SetBody("text/html", body.String())

	// 发送邮件
	d := gomail.NewDialer(s.host, s.port, s.username, s.password)
	if err := d.DialAndSend(m); err != nil {
		log.Printf("Failed to send email to %s: %v", to, err)
		return fmt.Errorf("发送邮件失败: %w", err)
	}

	log.Printf("Email sent successfully to %s", to)
	return nil
}
