package controller

import (
	"image/color"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mojocn/base64Captcha"
	"github.com/rushairer/gouno"
)

type CaptchaController struct {
	store       base64Captcha.Store
	captchaType string
}

func NewCaptchaController(captchaType string) *CaptchaController {
	log.Println("captcha type:", captchaType)
	return &CaptchaController{
		store:       base64Captcha.DefaultMemStore,
		captchaType: captchaType,
	}
}

func (c *CaptchaController) Generate(ctx *gin.Context) {
	var driver base64Captcha.Driver
	switch c.captchaType {
	case "math":
		driver = base64Captcha.NewDriverMath(80, 240, 1, 2, &color.RGBA{R: 255, G: 255, B: 255, A: 255}, nil, []string{}).ConvertFonts()
	case "chinese":
		driver = base64Captcha.NewDriverChinese(80, 240, 1, 2, 4, base64Captcha.TxtChineseCharaters, &color.RGBA{R: 255, G: 255, B: 255, A: 255}, nil, []string{}).ConvertFonts()
	case "audio":
		driver = base64Captcha.DefaultDriverAudio
	case "string":
		driver = base64Captcha.NewDriverString(80, 240, 1, 2, 4, base64Captcha.TxtAlphabet, &color.RGBA{R: 255, G: 255, B: 255, A: 255}, nil, []string{})
	default:
		driver = base64Captcha.DefaultDriverDigit
	}
	cp := base64Captcha.NewCaptcha(driver, c.store)
	id, base64String, answer, err := cp.Generate()
	log.Println(answer, id)
	if err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}

	ctx.Header("Content-Type", "application/json; charset=utf-8")
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"id": id, "data": base64String}))
}
