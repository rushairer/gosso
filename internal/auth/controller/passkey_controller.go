package controller

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountRepository "github.com/rushairer/gosso/internal/account/repository"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
	"github.com/rushairer/gosso/middleware"
)

// passkeyLoginErrorMap maps passkey login errors to HTTP responses.
var passkeyLoginErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrPasskeyNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "login failed"}},
}

// passkeyDeleteErrorMap maps passkey credential deletion errors to HTTP responses.
var passkeyDeleteErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrCredentialOwnership, Mapping: controllerutil.ErrorMapping{Status: http.StatusForbidden, Message: "credential does not belong to account"}},
	{Sentinel: accountRepository.ErrCredentialNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "credential not found"}},
}

// passkeyOptionsResponse constructs the passkey options response body.
func passkeyOptionsResponse(options any, requestID string) gin.H {
	return gin.H{
		"options":    options,
		"request_id": requestID,
	}
}

// passkeyAuthService defines the auth service methods used by PasskeyController.
type passkeyAuthService interface {
	LoginByPasskey(ctx context.Context, accountID, ip, userAgent string) (*authService.LoginResult, error)
	ValidateMFAToken(ctx context.Context, mfaToken string) (*tokenDomain.AccessTokenClaims, error)
	MarkPasskeyMFAVerified(ctx context.Context, mfaTokenJTI string) error
	CompletePasskeyMFALogin(ctx context.Context, mfaToken, ip, userAgent string) (*authService.LoginResult, error)
}

// PasskeyController handles Passkey authentication endpoints.
type PasskeyController struct {
	passkeySvc *authService.PasskeyService
	authSvc    passkeyAuthService
	tokenMgr   authService.TokenManager
	logger     *zap.Logger
}

// NewPasskeyController creates a new Passkey controller instance.
func NewPasskeyController(
	passkeySvc *authService.PasskeyService,
	authSvc passkeyAuthService,
	tokenMgr authService.TokenManager,
	logger *zap.Logger,
) *PasskeyController {
	return &PasskeyController{
		passkeySvc: passkeySvc,
		authSvc:    authSvc,
		tokenMgr:   tokenMgr,
		logger:     logger,
	}
}

// RegisterRoutes registers Passkey routes.
func (c *PasskeyController) RegisterRoutes(rg *gin.RouterGroup, jwtAuth gin.HandlerFunc, passkeyRateLimit gin.HandlerFunc) {
	passkey := rg.Group("/passkey")
	{
		// Passkey registration (requires authentication)
		passkey.POST("/register/begin", jwtAuth, c.RegisterBegin)
		passkey.POST("/register/complete", jwtAuth, c.RegisterComplete)

		// Login (no authentication required, but rate-limited)
		passkey.POST("/login/begin", passkeyRateLimit, c.LoginBegin)
		passkey.POST("/login/complete", passkeyRateLimit, c.LoginComplete)
	}

	// Passkey management (requires authentication)
	passkeys := rg.Group("/passkeys")
	{
		passkeys.GET("", jwtAuth, c.ListCredentials)
		passkeys.DELETE("/:id", jwtAuth, c.DeleteCredential)
	}

	// Passkey MFA (no JWT required, but requires mfa_token)
	mfaPasskey := rg.Group("/passkey/mfa")
	mfaPasskey.Use(passkeyRateLimit)
	{
		mfaPasskey.POST("/begin", c.MFABegin)
		mfaPasskey.POST("/complete", c.MFAComplete)
	}
}

// RegisterBegin POST /api/auth/passkey/register/begin
func (c *PasskeyController) RegisterBegin(ctx *gin.Context) {
	accountID, username, displayName, ok := c.resolveAccountForPasskey(ctx)
	if !ok {
		return
	}

	options, requestID, err := c.passkeySvc.BeginRegistration(ctx, accountID, username, displayName)
	if err != nil {
		c.logger.Error("Failed to begin passkey registration", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin registration"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(passkeyOptionsResponse(options, requestID)))
}

// RegisterComplete POST /api/auth/passkey/register/complete
func (c *PasskeyController) RegisterComplete(ctx *gin.Context) {
	requestID, ok := controllerutil.ValidateUUID(ctx, ctx.Query("request_id"), "request_id")
	if !ok {
		return
	}

	accountID, username, displayName, ok := c.resolveAccountForPasskey(ctx)
	if !ok {
		return
	}

	cred, err := c.passkeySvc.CompleteRegistration(ctx, requestID, accountID, username, displayName, ctx.Request)
	if err != nil {
		c.logger.Error("Failed to complete passkey registration", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "registration failed"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"id":   cred.ID,
		"name": cred.Name,
	}))
}

// resolveAccountForPasskey extracts the authenticated account's ID, username, and display name.
func (c *PasskeyController) resolveAccountForPasskey(ctx *gin.Context) (accountID, username, displayName string, ok bool) {
	accountID, ok = middleware.RequireAccountID(ctx)
	if !ok {
		return "", "", "", false
	}

	username, displayName, err := c.passkeySvc.ResolveAccountForRegistration(ctx, accountID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "account not found"))
		return "", "", "", false
	}
	return accountID, username, displayName, true
}

// LoginBeginRequest is the passkey login begin request body.
type LoginBeginRequest struct {
	AccountID string `json:"account_id"` // Optional; if empty, uses discoverable login
}

// LoginBegin POST /api/auth/passkey/login/begin
func (c *PasskeyController) LoginBegin(ctx *gin.Context) {
	var req LoginBeginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if req.AccountID != "" {
		if _, err := uuid.Parse(req.AccountID); err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid account_id format"))
			return
		}
		options, requestID, err := c.passkeySvc.BeginLogin(ctx, req.AccountID)
		if err != nil {
			controllerutil.HandleServiceError(ctx, c.logger, err, passkeyLoginErrorMap,
				http.StatusInternalServerError, "Failed to begin passkey login")
			return
		}
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(passkeyOptionsResponse(options, requestID)))
		return
	}

	options, requestID, err := c.passkeySvc.BeginDiscoverableLogin(ctx)
	if err != nil {
		c.logger.Error("Failed to begin discoverable login", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin login"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(passkeyOptionsResponse(options, requestID)))
}

// LoginCompleteRequest is the passkey login complete request body.
type LoginCompleteRequest struct {
	RequestID string `json:"request_id" binding:"required"`
}

// LoginComplete POST /api/auth/passkey/login/complete
func (c *PasskeyController) LoginComplete(ctx *gin.Context) {
	var req LoginCompleteRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	accountID, _, err := c.passkeySvc.CompleteLogin(ctx, req.RequestID, ctx.Request)
	if err != nil {
		c.logger.Error("Failed to complete passkey login", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "login failed"))
		return
	}

	// Complete full login flow with accountID (create session, generate tokens)
	loginResult, err := c.authSvc.LoginByPasskey(ctx, accountID, ctx.ClientIP(), ctx.Request.UserAgent())
	if err != nil {
		c.logger.Error("Passkey login failed", zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "login failed"))
		return
	}

	if loginResult.RequiresMFA {
		controllerutil.SetNoCacheHeaders(ctx)
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(mfaRequiredResponse(loginResult.AccessToken, loginResult.MFATypes)))
		return
	}

	controllerutil.SetNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		loginResult.AccessToken, loginResult.RefreshToken, loginResult.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

// MFABeginRequest is the passkey MFA begin request body.
type MFABeginRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
}

// MFABegin POST /api/auth/passkey/mfa/begin
func (c *PasskeyController) MFABegin(ctx *gin.Context) {
	var req MFABeginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if c.passkeySvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "passkey not available"))
		return
	}

	// Validate mfa token via authSvc and retrieve accountID
	claims, err := c.authSvc.ValidateMFAToken(ctx, req.MFAToken)
	if err != nil {
		c.logger.Warn("Invalid MFA token for passkey begin", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid mfa token"))
		return
	}

	options, requestID, err := c.passkeySvc.BeginMFALogin(ctx, claims.AccountID)
	if err != nil {
		c.logger.Error("Failed to begin passkey MFA", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin MFA"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(passkeyOptionsResponse(options, requestID)))
}

// MFACompleteRequest is the passkey MFA complete request body.
type MFACompleteRequest struct {
	MFAToken  string `json:"mfa_token" binding:"required"`
	RequestID string `json:"request_id" binding:"required"`
}

// MFAComplete POST /api/auth/passkey/mfa/complete
func (c *PasskeyController) MFAComplete(ctx *gin.Context) {
	var req MFACompleteRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	claims, err := c.authSvc.ValidateMFAToken(ctx, req.MFAToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid mfa token"))
		return
	}

	if err := c.passkeySvc.CompleteMFALogin(ctx, req.RequestID, claims.AccountID, ctx.Request); err != nil {
		c.logger.Error("Failed to complete passkey MFA", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "passkey verification failed"))
		return
	}

	// Mark passkey MFA as verified (consumed by CompletePasskeyMFALogin below).
	// Key is namespaced by MFA token JTI to prevent concurrent login interference.
	if err := c.authSvc.MarkPasskeyMFAVerified(ctx, claims.ID); err != nil {
		c.logger.Error("Failed to mark passkey MFA verified",
			zap.Error(err),
			zap.String("account_id", utility.MaskOpaqueID(claims.AccountID)))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "internal server error"))
		return
	}

	// Complete login directly — no separate /mfa/verify call needed
	result, err := c.authSvc.CompletePasskeyMFALogin(ctx, req.MFAToken, ctx.ClientIP(), ctx.Request.UserAgent())
	if err != nil {
		c.logger.Error("Passkey MFA login failed", zap.String("account_id", utility.MaskOpaqueID(claims.AccountID)), zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "MFA verification failed"))
		return
	}

	controllerutil.SetNoCacheHeaders(ctx)

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

// ListCredentials GET /api/auth/passkeys
func (c *PasskeyController) ListCredentials(ctx *gin.Context) {
	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
	}

	creds, err := c.passkeySvc.ListCredentials(ctx, accountID)
	if err != nil {
		c.logger.Error("Failed to list passkeys", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to list passkeys"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(creds))
}

// DeleteCredential DELETE /api/auth/passkeys/:id
func (c *PasskeyController) DeleteCredential(ctx *gin.Context) {
	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
	}

	credentialID := ctx.Param("id")
	if credentialID == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "credential id required"))
		return
	}
	if _, err := uuid.Parse(credentialID); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid credential id"))
		return
	}

	if err := c.passkeySvc.DeleteCredential(ctx, accountID, credentialID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, passkeyDeleteErrorMap,
			http.StatusInternalServerError, "Failed to delete passkey")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"deleted": true}))
}
