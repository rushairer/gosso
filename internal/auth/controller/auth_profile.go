package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	authService "github.com/rushairer/gosso/internal/auth/service"
)

// UpdateProfileRequest update profile request body
type UpdateProfileRequest struct {
	DisplayName string `json:"display_name" binding:"required,max=100"`
}

// UpdateProfile PUT /api/v1/auth/profile
func (c *AuthController) UpdateProfile(ctx *gin.Context) {
	var req UpdateProfileRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	account, err := c.authSvc.UpdateProfile(ctx, tc.AccountID, req.DisplayName)
	if err != nil {
		c.logger.Error("Failed to update profile", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to update profile"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"id":           account.ID,
		"username":     account.Username,
		"display_name": account.DisplayName,
	}))
}

// RequestEmailChangeRequest request email change body
type RequestEmailChangeRequest struct {
	NewEmail string `json:"new_email" binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,max=72"`
}

// RequestEmailChange POST /api/v1/auth/profile/email/change/request
func (c *AuthController) RequestEmailChange(ctx *gin.Context) {
	var req RequestEmailChangeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	// 1. Verify current password
	if err := c.authSvc.VerifyCurrentPassword(ctx, tc.AccountID, req.Password); err != nil {
		if errors.Is(err, authService.ErrInvalidCredentials) {
			ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "incorrect password"))
			return
		}
		c.logger.Error("Password verification failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to verify password"))
		return
	}

	// 2. Check if new email is already in use
	available, err := c.authSvc.IsEmailAvailable(ctx, req.NewEmail)
	if err != nil {
		c.logger.Error("Failed to check email availability", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to check email availability"))
		return
	}
	if !available {
		ctx.JSON(http.StatusConflict, gouno.NewErrorResponse(http.StatusConflict, "email already in use"))
		return
	}

	// 3. Send verification code to the NEW email
	if err := c.verificationSvc.SendCode(ctx, "email", req.NewEmail, tc.AccountID); err != nil {
		c.logger.Error("Failed to send verification code for email change", zap.Error(err))
		if errors.Is(err, authService.ErrCooldownActive) {
			ctx.JSON(http.StatusTooManyRequests, gouno.NewErrorResponse(http.StatusTooManyRequests, "too many requests, please try again later"))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to send verification code"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("verification code sent"))
}

// ConfirmEmailChangeRequest confirm email change body
type ConfirmEmailChangeRequest struct {
	NewEmail string `json:"new_email" binding:"required,email,max=254"`
	Code     string `json:"code" binding:"required,max=32"`
}

// ConfirmEmailChange POST /api/v1/auth/profile/email/change/confirm
func (c *AuthController) ConfirmEmailChange(ctx *gin.Context) {
	var req ConfirmEmailChangeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	// 1. Verify code matches and belongs to this account
	if err := c.verificationSvc.VerifyCodeForAccount(ctx, "email", req.NewEmail, req.Code, tc.AccountID); err != nil {
		if errors.Is(err, authService.ErrVerificationCodeExpired) || errors.Is(err, authService.ErrVerificationCodeInvalid) || errors.Is(err, authService.ErrVerificationCodeExhausted) {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid or expired verification code"))
			return
		}
		c.logger.Error("Email change verification code failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to verify code"))
		return
	}

	// 2. Perform database update
	if err := c.authSvc.UpdateEmail(ctx, tc.AccountID, req.NewEmail); err != nil {
		if errors.Is(err, authService.ErrEmailAlreadyInUse) {
			ctx.JSON(http.StatusConflict, gouno.NewErrorResponse(http.StatusConflict, "email already in use"))
			return
		}
		c.logger.Error("Failed to update email", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to update email"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("email updated successfully"))
}
