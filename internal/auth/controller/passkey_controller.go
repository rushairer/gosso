package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/internal/auth/middleware"
	authService "github.com/rushairer/gosso/internal/auth/service"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

// PasskeyController Passkey 控制器
type PasskeyController struct {
	passkeySvc  *authService.PasskeyService
	authSvc     *authService.AuthService
	accountSvc  accountService.AccountService
	logger      *zap.Logger
}

// NewPasskeyController 创建 Passkey 控制器实例
func NewPasskeyController(
	passkeySvc *authService.PasskeyService,
	authSvc *authService.AuthService,
	accountSvc accountService.AccountService,
	logger *zap.Logger,
) *PasskeyController {
	return &PasskeyController{
		passkeySvc: passkeySvc,
		authSvc:    authSvc,
		accountSvc: accountSvc,
		logger:     logger,
	}
}

// RegisterRoutes 注册 Passkey 路由
func (c *PasskeyController) RegisterRoutes(rg *gin.RouterGroup, jwtAuth gin.HandlerFunc) {
	passkey := rg.Group("/passkey")
	{
		// 注册 passkey（需要登录）
		passkey.POST("/register/begin", jwtAuth, c.RegisterBegin)
		passkey.POST("/register/complete", jwtAuth, c.RegisterComplete)

		// 登录（无需认证）
		passkey.POST("/login/begin", c.LoginBegin)
		passkey.POST("/login/complete", c.LoginComplete)
	}

	// Passkey 管理（需要登录）
	passkeys := rg.Group("/passkeys")
	{
		passkeys.GET("", jwtAuth, c.ListCredentials)
		passkeys.DELETE("/:id", jwtAuth, c.DeleteCredential)
	}

	// Passkey MFA（无需 JWT，但需要 mfa_token）
	mfaPasskey := rg.Group("/passkey/mfa")
	{
		mfaPasskey.POST("/begin", c.MFABegin)
		mfaPasskey.POST("/complete", c.MFAComplete)
	}
}

// RegisterBegin POST /api/auth/passkey/register/begin
func (c *PasskeyController) RegisterBegin(ctx *gin.Context) {
	accountID := ctx.GetString(middleware.ContextKeyAccountID)
	if accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}

	account, err := c.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "account not found"))
		return
	}

	username := accountID
	if account.Username != nil {
		username = *account.Username
	}
	displayName := username
	if account.DisplayName != "" {
		displayName = account.DisplayName
	}

	options, err := c.passkeySvc.BeginRegistration(ctx, accountID, username, displayName)
	if err != nil {
		c.logger.Error("Failed to begin passkey registration", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin registration"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(options))
}

// RegisterComplete POST /api/auth/passkey/register/complete
func (c *PasskeyController) RegisterComplete(ctx *gin.Context) {
	accountID := ctx.GetString(middleware.ContextKeyAccountID)
	if accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}

	account, err := c.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "account not found"))
		return
	}

	username := accountID
	if account.Username != nil {
		username = *account.Username
	}
	displayName := username
	if account.DisplayName != "" {
		displayName = account.DisplayName
	}

	cred, err := c.passkeySvc.CompleteRegistration(ctx, accountID, username, displayName, ctx.Request)
	if err != nil {
		c.logger.Error("Failed to complete passkey registration", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "registration failed"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"id":    cred.ID,
		"name":  cred.Name,
	}))
}

// LoginBeginRequest Passkey 登录开始请求体
type LoginBeginRequest struct {
	AccountID string `json:"account_id"` // 可选，不填则使用 discoverable login
}

// LoginBegin POST /api/auth/passkey/login/begin
func (c *PasskeyController) LoginBegin(ctx *gin.Context) {
	var req LoginBeginRequest
	_ = ctx.ShouldBindJSON(&req)

	if req.AccountID != "" {
		options, requestID, err := c.passkeySvc.BeginLogin(ctx, req.AccountID)
		if err != nil {
			c.logger.Error("Failed to begin passkey login", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin login"))
			return
		}
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
			"options":    options,
			"request_id": requestID,
		}))
		return
	}

	options, requestID, err := c.passkeySvc.BeginDiscoverableLogin(ctx)
	if err != nil {
		c.logger.Error("Failed to begin discoverable login", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin login"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"options":    options,
		"request_id": requestID,
	}))
}

// LoginCompleteRequest Passkey 登录完成请求体
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

	// 使用 accountID 完成完整登录流程（创建会话、生成 tokens）
	account, err := c.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "account not found"))
		return
	}

	loginResult, err := c.authSvc.LoginByUsernamePassword(ctx, &authService.LoginRequest{
		Username:  accountID, // passkey 已验证身份，直接登录
		Password:  "",        // 跳过密码验证
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
	if err != nil {
		// passkey 登录不走密码验证，直接创建 session
		c.logger.Warn("Passkey login orchestration failed, account may need password",
			zap.String("account_id", accountID), zap.Error(err))
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
			"account_id":  accountID,
			"username":    account.Username,
			"message":     "Passkey verified. Please complete login with password or MFA.",
		}))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"access_token":  loginResult.AccessToken,
		"refresh_token": loginResult.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    900,
		"session_id":    loginResult.Session.ID.String(),
	}))
}

// MFABeginRequest Passkey MFA 开始请求体
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

	// 验证 mfa_token 获取 accountID
	tokenSvc := c.authSvc.PasskeyService()
	if tokenSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "passkey not available"))
		return
	}

	// 使用 authSvc 验证 mfa token 并获取 accountID
	claims, err := c.authSvc.ValidateMFAToken(ctx, req.MFAToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid mfa token"))
		return
	}

	options, err := c.passkeySvc.BeginMFALogin(ctx, claims.AccountID)
	if err != nil {
		c.logger.Error("Failed to begin passkey MFA", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to begin MFA"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(options))
}

// MFACompleteRequest Passkey MFA 完成请求体
type MFACompleteRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
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

	if err := c.passkeySvc.CompleteMFALogin(ctx, claims.AccountID, ctx.Request); err != nil {
		c.logger.Error("Failed to complete passkey MFA", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "passkey verification failed"))
		return
	}

	// 标记 passkey MFA 已验证
	if err := c.authSvc.MarkPasskeyMFAVerified(ctx, claims.AccountID); err != nil {
		c.logger.Warn("Failed to mark passkey MFA verified", zap.Error(err))
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"verified": true,
		"message":  "Passkey verified. Please call /api/auth/mfa/verify to complete login.",
	}))
}

// ListCredentials GET /api/auth/passkeys
func (c *PasskeyController) ListCredentials(ctx *gin.Context) {
	accountID := ctx.GetString(middleware.ContextKeyAccountID)
	if accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
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
	accountID := ctx.GetString(middleware.ContextKeyAccountID)
	if accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}

	credentialID := ctx.Param("id")
	if credentialID == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "credential id required"))
		return
	}

	if err := c.passkeySvc.DeleteCredential(ctx, accountID, credentialID); err != nil {
		c.logger.Error("Failed to delete passkey", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"deleted": true}))
}
