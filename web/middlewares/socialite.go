package middlewares

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)

type SocialiteMiddleware struct {
}

func NewSocialiteMiddleware() *SocialiteMiddleware {
	return &SocialiteMiddleware{}
}

func (m *SocialiteMiddleware) GetProviderName(ctx *gin.Context) {
	gothic.GetProviderName = func(r *http.Request) (string, error) {
		return ctx.Param("provider"), nil
	}
}
