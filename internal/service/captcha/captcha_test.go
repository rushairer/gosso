package captcha

import (
	"testing"
)

func TestCaptchaService_Generate(t *testing.T) {
	service := NewCaptchaService()

	tests := []struct {
		name        string
		captchaType CaptchaType
	}{
		{"数字验证码", TypeDigit},
		{"数学验证码", TypeMath},
		{"中文验证码", TypeChinese},
		{"字符串验证码", TypeString},
		{"音频验证码", TypeAudio},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.Generate(tt.captchaType)
			if err != nil {
				t.Errorf("Generate() error = %v", err)
				return
			}

			if result.ID == "" {
				t.Error("Generate() ID is empty")
			}

			if result.Data == "" {
				t.Error("Generate() Data is empty")
			}

			if result.Answer == "" {
				t.Error("Generate() Answer is empty")
			}

			t.Logf("Generated captcha: ID=%s, Answer=%s", result.ID, result.Answer)
		})
	}
}

func TestCaptchaService_Verify(t *testing.T) {
	service := NewCaptchaService()

	// 生成验证码
	result, err := service.Generate(TypeDigit)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// 验证正确答案
	if !service.Verify(result.ID, result.Answer, false) {
		t.Error("Verify() failed for correct answer")
	}

	// 验证错误答案
	if service.Verify(result.ID, "wrong", false) {
		t.Error("Verify() should fail for wrong answer")
	}

	// 验证清除功能
	if !service.Verify(result.ID, result.Answer, true) {
		t.Error("Verify() failed for correct answer with clear=true")
	}

	// 再次验证应该失败（已清除）
	if service.Verify(result.ID, result.Answer, false) {
		t.Error("Verify() should fail after clear")
	}
}

func TestCaptchaService_NewCaptchaService(t *testing.T) {
	service := NewCaptchaService()
	if service == nil {
		t.Error("NewCaptchaService() returned nil")
	}

	if service.store == nil {
		t.Error("NewCaptchaService() store is nil")
	}
}
