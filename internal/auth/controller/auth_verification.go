package controller

import (
	"net/http"
	"net/mail"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	utility "github.com/rushairer/gosso/internal/utility"
)

// sendVerificationErrorMap maps verification code send errors to HTTP responses.
var sendVerificationErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrServiceUnavailable, Mapping: controllerutil.ErrorMapping{Status: http.StatusServiceUnavailable, Message: "service temporarily unavailable"}},
	{Sentinel: authService.ErrCooldownActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many requests, please try again later"}},
	{Sentinel: authService.ErrUnsupportedType, Mapping: controllerutil.ErrorMapping{Status: http.StatusBadRequest, Message: "unsupported credential type"}},
}

// SendVerificationRequest send verification code request body
type SendVerificationRequest struct {
	Type       string `json:"type" binding:"required"`               // "email"; "phone" is reserved until SMS is configured
	Identifier string `json:"identifier" binding:"required,max=255"` // email address or phone number
}

// SendVerification POST /api/auth/verify/send
func (c *AuthController) SendVerification(ctx *gin.Context) {
	var req SendVerificationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if req.Type != "email" && req.Type != "phone" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "type must be 'email' or 'phone'"))
		return
	}

	if req.Type == "email" {
		if _, err := mail.ParseAddress(req.Identifier); err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid email format"))
			return
		}
	}
	if req.Type == "phone" && !utility.ValidatePhoneFormat(req.Identifier) {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid phone format"))
		return
	}
	if req.Type == "phone" {
		ctx.JSON(http.StatusNotImplemented, gouno.NewErrorResponse(http.StatusNotImplemented, "phone verification is not yet supported"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	// Verify the identifier belongs to this account
	if err := c.verificationSvc.ValidateCredentialOwnership(ctx, tc.AccountID, string(accountDomain.CredentialTypeEmail), req.Identifier); err != nil {
		c.logger.Warn("Credential ownership validation failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	if err := c.verificationSvc.SendCode(ctx, req.Type, req.Identifier, tc.AccountID); err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, sendVerificationErrorMap,
			http.StatusInternalServerError, "failed to send verification code")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("verification code sent"))
}

// ConfirmVerificationRequest confirm verification code request body
type ConfirmVerificationRequest struct {
	Type       string `json:"type" binding:"required"`
	Identifier string `json:"identifier" binding:"required,max=255"`
	Code       string `json:"code" binding:"required,max=32"`
}

// ConfirmVerification POST /api/auth/verify/confirm
func (c *AuthController) ConfirmVerification(ctx *gin.Context) {
	var req ConfirmVerificationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if req.Type != "email" && req.Type != "phone" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "type must be 'email' or 'phone'"))
		return
	}

	// Phone verification is not yet supported — reject consistently with SendVerification.
	if req.Type == "phone" {
		ctx.JSON(http.StatusNotImplemented, gouno.NewErrorResponse(http.StatusNotImplemented, "phone verification is not yet supported"))
		return
	}

	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	// Validate verification code and check ownership
	if err := c.verificationSvc.VerifyCodeForAccount(ctx, req.Type, req.Identifier, req.Code, tc.AccountID); err != nil {
		c.logger.Warn("Verification code failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid verification code"))
		return
	}

	// Find credential and mark it as verified via service layer
	if err := c.authSvc.ConfirmVerificationCredential(ctx, req.Type, req.Identifier, tc.AccountID); err != nil {
		c.logger.Warn("Failed to confirm verification credential", zap.Error(err), zap.String("type", req.Type), zap.String("identifier", utility.MaskIdentifier(req.Type, req.Identifier)))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid verification code"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("credential verified"))
}
