package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mojocn/base64Captcha"
	"github.com/rushairer/gouno"
)

type CaptchaVerifyRequest struct {
	Captcha CaptchaData `json:"captcha_info"`
}

type CaptchaData struct {
	Id     string `json:"id"`
	Answer string `json:"answer"`
}

func RequireCaptchaMiddleware() gin.HandlerFunc {
	store := base64Captcha.DefaultMemStore
	return func(ctx *gin.Context) {
		body, err := ctx.GetRawData()
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "read request body error"))
			ctx.Abort()
			return
		}

		// 重置请求体
		ctx.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var req CaptchaVerifyRequest
		if err := json.Unmarshal(body, &req); err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "missing captcha info"))
			ctx.Abort()
			return
		}

		if !store.Verify(req.Captcha.Id, req.Captcha.Answer, true) {
			ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusUnauthorized, "captcha error"))
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}
