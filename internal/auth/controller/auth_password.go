package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	authService "github.com/rushairer/gosso/internal/auth/service"
	utility "github.com/rushairer/gosso/internal/utility"
)

// ForgotPasswordRequest forgot password request body
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPassword POST /api/auth/password/forgot
func (c *AuthController) ForgotPassword(ctx *gin.Context) {
	var req ForgotPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if err := c.passwordResetSvc.RequestReset(ctx, req.Email); err != nil {
		// Distinguish expected business errors from infrastructure failures.
		// Log infrastructure errors at Error level for alerting.
		if errors.Is(err, authService.ErrServiceUnavailable) || errors.Is(err, authService.ErrPasswordCooldown) {
			c.logger.Warn("Password reset request denied", zap.String("email", utility.MaskEmail(req.Email)), zap.Error(err))
		} else {
			c.logger.Error("Password reset request failed unexpectedly", zap.String("email", utility.MaskEmail(req.Email)), zap.Error(err))
		}
	}

	// Always return 200 to prevent email enumeration
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("if the email exists, a reset link has been sent"))
}

// ResetPasswordRequest reset password request body
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=12,max=128"`
}

// ResetPassword POST /api/auth/password/reset
func (c *AuthController) ResetPassword(ctx *gin.Context) {
	var req ResetPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if err := c.passwordResetSvc.VerifyAndReset(ctx, req.Token, req.NewPassword); err != nil {
		c.logger.Warn("Password reset failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid or expired reset token"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("password has been reset successfully"))
}
