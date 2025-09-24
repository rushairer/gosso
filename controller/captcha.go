package controller

import (
	"log"
	"net/http"

	"gosso/internal/service/captcha"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
)

type CaptchaController struct {
	captchaService *captcha.CaptchaService
	captchaType    captcha.CaptchaType
}

func NewCaptchaController(captchaType string) *CaptchaController {
	return &CaptchaController{
		captchaService: captcha.NewCaptchaService(),
		captchaType:    captcha.CaptchaType(captchaType),
	}
}

func (c *CaptchaController) Generate(ctx *gin.Context) {
	result, err := c.captchaService.Generate(c.captchaType)
	if err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}

	// 记录答案用于调试（生产环境应该移除或使用更安全的日志方式）
	log.Printf("Generated captcha: ID=%s, Answer=%s", result.ID, result.Answer)

	ctx.Header("Content-Type", "application/json; charset=utf-8")
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"id":   result.ID,
		"data": result.Data,
	}))
}
