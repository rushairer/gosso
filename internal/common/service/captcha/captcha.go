package captcha

import (
	"image/color"

	"github.com/mojocn/base64Captcha"
)

// CaptchaService 验证码服务
type CaptchaService struct {
	store base64Captcha.Store
}

// CaptchaResult 验证码生成结果
type CaptchaResult struct {
	ID     string `json:"id"`
	Data   string `json:"data"`
	Answer string `json:"-"` // 答案不返回给前端，仅用于日志
}

// CaptchaType 验证码类型
type CaptchaType string

const (
	TypeDigit   CaptchaType = "digit"
	TypeMath    CaptchaType = "math"
	TypeChinese CaptchaType = "chinese"
	TypeAudio   CaptchaType = "audio"
	TypeString  CaptchaType = "string"
)

// NewCaptchaService 创建验证码服务
func NewCaptchaService() *CaptchaService {
	return &CaptchaService{
		store: base64Captcha.DefaultMemStore,
	}
}

// Generate 生成验证码
func (s *CaptchaService) Generate(captchaType CaptchaType) (*CaptchaResult, error) {
	driver := s.createDriver(captchaType)
	cp := base64Captcha.NewCaptcha(driver, s.store)

	id, base64String, answer, err := cp.Generate()
	if err != nil {
		return nil, err
	}

	return &CaptchaResult{
		ID:     id,
		Data:   base64String,
		Answer: answer,
	}, nil
}

// Verify 验证验证码
func (s *CaptchaService) Verify(id, answer string, clear bool) bool {
	return s.store.Verify(id, answer, clear)
}

// createDriver 根据类型创建驱动
func (s *CaptchaService) createDriver(captchaType CaptchaType) base64Captcha.Driver {
	bgColor := &color.RGBA{R: 255, G: 255, B: 255, A: 255}

	switch captchaType {
	case TypeMath:
		return base64Captcha.NewDriverMath(80, 240, 1, 2, bgColor, nil, []string{}).ConvertFonts()
	case TypeChinese:
		return base64Captcha.NewDriverChinese(80, 240, 1, 2, 4, base64Captcha.TxtChineseCharaters, bgColor, nil, []string{}).ConvertFonts()
	case TypeAudio:
		return base64Captcha.DefaultDriverAudio
	case TypeString:
		return base64Captcha.NewDriverString(80, 240, 1, 2, 4, base64Captcha.TxtAlphabet, bgColor, nil, []string{})
	default:
		return base64Captcha.DefaultDriverDigit
	}
}
