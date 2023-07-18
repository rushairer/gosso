package controllers

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/rushairer/gosso/core/socialite"
)

type SocialiteController struct {
	homePagePath     string
	signInPagePath   string
	socialiteService *socialite.SocialiteService
}

func NewSocialsController(
	homePagePath string,
	signInPagePath string,
	socialiteService *socialite.SocialiteService,
) *SocialiteController {
	return &SocialiteController{
		homePagePath:     homePagePath,
		signInPagePath:   signInPagePath,
		socialiteService: socialiteService,
	}
}

func (c *SocialiteController) SignIn(ctx *gin.Context) {
	c.socialiteService.UseProviders(ctx)

	if gothUser, err := gothic.CompleteUserAuth(ctx.Writer, ctx.Request); err == nil {
		c.saveUserAndRedirect(ctx, gothUser)
	} else {
		log.Println("socialite sign-in error:", err)
		gothic.BeginAuthHandler(ctx.Writer, ctx.Request)
	}
}

func (c SocialiteController) Callback(ctx *gin.Context) {
	c.socialiteService.UseProviders(ctx)

	if gothUser, err := gothic.CompleteUserAuth(ctx.Writer, ctx.Request); err == nil {
		c.saveUserAndRedirect(ctx, gothUser)
	} else {
		// 因为会出现 gothUser, err 同时有值的情况，比如 github 没有设置主邮箱
		// 所以不会因为 err 终断跳转
		log.Println("socialite callback error:", err, gothUser)
	}
}

func (c *SocialiteController) saveUserAndRedirect(ctx *gin.Context, gothUser goth.User) {

}
