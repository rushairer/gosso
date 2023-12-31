package controllers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/rushairer/gosso/core/authentication"
	"github.com/rushairer/gosso/core/socialite"
)

type SocialiteController struct {
	homePagePath          string
	signInPagePath        string
	socialiteService      *socialite.SocialiteService
	authenticationService *authentication.AuthenticationService
}

func NewSocialsController(
	homePagePath string,
	signInPagePath string,
	socialiteService *socialite.SocialiteService,
	authenticationService *authentication.AuthenticationService,
) *SocialiteController {
	return &SocialiteController{
		homePagePath:          homePagePath,
		signInPagePath:        signInPagePath,
		socialiteService:      socialiteService,
		authenticationService: authenticationService,
	}
}

func (c *SocialiteController) SignIn(ctx *gin.Context) {
	c.socialiteService.UseProviders(ctx)

	if gothUser, err := gothic.CompleteUserAuth(ctx.Writer, ctx.Request); err == nil {
		c.saveUserAndRedirect(ctx, gothUser)
	} else {
		log.Println("[socialite]", "sign-in error:", err)
		gothic.BeginAuthHandler(ctx.Writer, ctx.Request)
	}
}

func (c SocialiteController) Callback(ctx *gin.Context) {
	c.socialiteService.UseProviders(ctx)

	gothUser, err := gothic.CompleteUserAuth(ctx.Writer, ctx.Request)
	if err != nil {
		// 因为会出现 gothUser, err 同时有值的情况，比如 github 没有设置主邮箱
		// 所以不会因为 err 终断跳转
		log.Println("[socialite]", "callback error:", err, gothUser)
		ctx.JSON(http.StatusInternalServerError, err)
	}

	if len(gothUser.UserID) > 0 {
		c.saveUserAndRedirect(ctx, gothUser)
	}
}

func (c *SocialiteController) saveUserAndRedirect(ctx *gin.Context, gothUser goth.User) {
	if err := c.authenticationService.SaveUser(ctx, gothUser); err != nil {
		log.Println("[socialite]", "save user error:", err)
	}
	ctx.Redirect(http.StatusSeeOther, c.homePagePath)
}
