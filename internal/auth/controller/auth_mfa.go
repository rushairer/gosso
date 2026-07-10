package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	"github.com/rushairer/gosso/internal/utility"
)

// MFAEnroll POST /api/auth/mfa/enroll
func (c *AuthController) MFAEnroll(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	mfaSvc := c.authSvc.MFAService()
	if mfaSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not available"))
		return
	}

	enrollment, err := mfaSvc.EnrollTOTP(ctx, tc.AccountID)
	if err != nil {
		// Distinguish configuration errors (503) from runtime failures (500).
		if errors.Is(err, authService.ErrInvalidConfig) {
			c.logger.Error("MFA enrollment failed due to misconfiguration", zap.Error(err))
			ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not configured"))
			return
		}
		c.logger.Error("MFA enrollment failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to enroll MFA"))
		return
	}

	controllerutil.SetNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(enrollment))
}

// MFAActivateRequest MFA activation request body
type MFAActivateRequest struct {
	Code string `json:"code" binding:"required,max=8"`
}

// MFAActivate POST /api/auth/mfa/activate
func (c *AuthController) MFAActivate(ctx *gin.Context) {
	var req MFAActivateRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	mfaSvc := c.authSvc.MFAService()
	if mfaSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not available"))
		return
	}

	if err := mfaSvc.ActivateTOTP(ctx, tc.AccountID, req.Code); err != nil {
		c.logger.Warn("MFA activation failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid activation code"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("TOTP activated"))
}

// MFADisableRequest MFA disable request body
type MFADisableRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
}

// MFADisable DELETE /api/auth/mfa
func (c *AuthController) MFADisable(ctx *gin.Context) {
	var req MFADisableRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	mfaSvc := c.authSvc.MFAService()
	if mfaSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not available"))
		return
	}

	// Step-up authentication: require current password to disable MFA.
	// This prevents an attacker with a stolen session from stripping MFA protection.
	if err := c.authSvc.VerifyCurrentPassword(ctx, tc.AccountID, req.CurrentPassword); err != nil {
		c.logger.Warn("MFA disable rejected — password verification failed",
			zap.String("account_id", utility.MaskOpaqueID(tc.AccountID)), zap.Error(err))
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "invalid password"))
		return
	}

	if err := mfaSvc.DisableTOTP(ctx, tc.AccountID); err != nil {
		c.logger.Error("MFA disable failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to disable MFA"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("MFA disabled"))
}

// MFAGenerateBackupCodes POST /api/auth/mfa/backup-codes
func (c *AuthController) MFAGenerateBackupCodes(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	mfaSvc := c.authSvc.MFAService()
	if mfaSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not available"))
		return
	}

	codes, err := mfaSvc.GenerateBackupCodes(ctx, tc.AccountID)
	if err != nil {
		c.logger.Error("Backup codes generation failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to generate backup codes"))
		return
	}

	// Backup codes are sensitive — prevent caching by proxies or browsers.
	controllerutil.SetNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"backup_codes": codes,
	}))
}

// MFAStatus GET /api/auth/mfa
func (c *AuthController) MFAStatus(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	mfaSvc := c.authSvc.MFAService()
	if mfaSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not available"))
		return
	}

	status, err := mfaSvc.GetMFAStatus(ctx, tc.AccountID)
	if err != nil {
		c.logger.Error("Failed to get MFA status", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to get MFA status"))
		return
	}

	controllerutil.SetNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(status))
}
