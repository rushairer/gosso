package controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountService "github.com/rushairer/gosso/internal/account/service"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/utility"
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
	NewPassword string `json:"new_password" binding:"required,min=12,max=72"`
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

// ChangePasswordRequest holds current and new passwords
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
	NewPassword     string `json:"new_password" binding:"required,min=12,max=72"`
}

// ChangePassword POST /api/v1/auth/password/change
func (c *AuthController) ChangePassword(ctx *gin.Context) {
	var req ChangePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body or password too short/long"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	// 1. Verify old password first (crucial step-up security)
	if err := c.authSvc.VerifyCurrentPassword(ctx, tc.AccountID, req.CurrentPassword); err != nil {
		c.logger.Warn("Self password change rejected — current password verification failed",
			zap.String("account_id", utility.MaskOpaqueID(tc.AccountID)), zap.Error(err))
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "incorrect current password"))
		return
	}

	// 2. Execute password change (which hashes and revokes other sessions)
	if err := c.authSvc.ChangePassword(ctx, tc.AccountID, req.CurrentPassword, req.NewPassword); err != nil {
		c.logger.Error("Self password change failed", zap.String("account_id", tc.AccountID), zap.Error(err))
		if errors.Is(err, accountService.ErrSamePassword) {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "new password must be different from current password"))
			return
		}
		if errors.Is(err, accountService.ErrAccountNotActive) {
			ctx.JSON(http.StatusConflict, gouno.NewErrorResponse(http.StatusConflict, err.Error()))
			return
		}
		if strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "hash") {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to change password"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("password changed successfully"))
}
