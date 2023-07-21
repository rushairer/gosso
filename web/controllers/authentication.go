package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/core/authentication"
)

type AuthenticationController struct {
	authenticationService *authentication.AuthenticationService
}

func NewAuthenticationController(
	authenticationService *authentication.AuthenticationService,
) *AuthenticationController {
	return &AuthenticationController{
		authenticationService: authenticationService,
	}
}

func (c *AuthenticationController) Profile(ctx *gin.Context) {
	if user, err := c.authenticationService.GetUserFromSession(ctx.Request); err == nil {
		ctx.JSON(http.StatusOK, user)
	}
}
