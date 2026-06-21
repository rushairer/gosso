package controller

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
)

// loginErrorMap maps login service errors to HTTP responses.
var loginErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrServiceUnavailable, Mapping: controllerutil.ErrorMapping{Status: http.StatusServiceUnavailable, Message: "service temporarily unavailable"}},
	{Sentinel: authService.ErrIPLocked, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many attempts from this IP, try again later"}},
	{Sentinel: authService.ErrMFARateLimited, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many MFA attempts, try again later"}},
}

// refreshErrorMap maps token refresh service errors to HTTP responses.
var refreshErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrServiceUnavailable, Mapping: controllerutil.ErrorMapping{Status: http.StatusServiceUnavailable, Message: "service temporarily unavailable"}},
	{Sentinel: authService.ErrIPLocked, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many attempts from this IP, try again later"}},
}

// mfaVerifyErrorMap maps MFA verification service errors to HTTP responses.
var mfaVerifyErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrServiceUnavailable, Mapping: controllerutil.ErrorMapping{Status: http.StatusServiceUnavailable, Message: "service temporarily unavailable"}},
	{Sentinel: authService.ErrMFARateLimited, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many MFA attempts, try again later"}},
}

// authServiceDeps defines the auth service methods used by AuthController.
type authServiceDeps interface {
	LoginByUsernamePassword(ctx context.Context, req *authService.LoginCommand) (*authService.LoginResult, error)
	VerifyMFALogin(ctx context.Context, mfaToken, mfaCode, mfaType, ip, userAgent string) (*authService.LoginResult, error)
	Logout(ctx context.Context, accountID, sessionID string, accessTokenJTI string, tokenExpiresAt time.Time) error
	RefreshTokens(ctx context.Context, refreshToken string) (*authService.RefreshResult, error)
	ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error)
	ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error)
	RevokeSession(ctx context.Context, accountID, sessionID string) error
	ConfirmVerificationCredential(ctx context.Context, credType, identifier, accountID string) error
	VerifyCurrentPassword(ctx context.Context, accountID, password string) error
	MFAService() *authService.MFAService
	PasskeyService() *authService.PasskeyService
}

// AuthController authentication controller
type AuthController struct {
	authSvc          authServiceDeps
	tokenMgr         authService.TokenManager
	socialSvc        *authService.SocialLoginService
	verificationSvc  *authService.VerificationService
	passwordResetSvc *authService.PasswordResetService
	secureCookie     bool
	logger           *zap.Logger
}

// NewAuthController creates a new instance of AuthController
func NewAuthController(
	authSvc authServiceDeps,
	tokenMgr authService.TokenManager,
	socialSvc *authService.SocialLoginService,
	verificationSvc *authService.VerificationService,
	passwordResetSvc *authService.PasswordResetService,
	secureCookie bool,
	logger *zap.Logger,
) *AuthController {
	return &AuthController{
		authSvc:          authSvc,
		tokenMgr:         tokenMgr,
		socialSvc:        socialSvc,
		verificationSvc:  verificationSvc,
		passwordResetSvc: passwordResetSvc,
		secureCookie:     secureCookie,
		logger:           logger,
	}
}

// AuthRouteConfig holds per-endpoint rate limiting middleware for auth routes.
type AuthRouteConfig struct {
	JWTAuth       gin.HandlerFunc // JWT authentication middleware for protected endpoints
	LoginLimit    gin.HandlerFunc // Rate limiter for login
	MFALimit      gin.HandlerFunc // Rate limiter for MFA operations
	PasswordLimit gin.HandlerFunc // Rate limiter for password operations
	RefreshLimit  gin.HandlerFunc // Rate limiter for token refresh
	VerifyLimit   gin.HandlerFunc // Rate limiter for verification
	SocialLimit   gin.HandlerFunc // Rate limiter for social login
	SessionLimit  gin.HandlerFunc // Rate limiter for session management
}

// RegisterRoutes registers authentication routes
func (c *AuthController) RegisterRoutes(rg *gin.RouterGroup, cfg AuthRouteConfig) {
	auth := rg.Group("/auth")
	{
		auth.POST("/login", withOptionalLimit(cfg.LoginLimit, c.Login)...)
		auth.POST("/refresh", withOptionalLimit(cfg.RefreshLimit, c.Refresh)...)

		// MFA verify uses mfa_token, not JWT
		auth.POST("/mfa/verify", withOptionalLimit(cfg.MFALimit, c.MFAVerify)...)

		// Social login endpoints (unauthenticated)
		auth.GET("/social/:provider", withOptionalLimit(cfg.SocialLimit, c.SocialAuthURL)...)
		auth.GET("/social/:provider/callback", withOptionalLimit(cfg.SocialLimit, c.SocialCallback)...)

		// Password reset endpoints (unauthenticated)
		auth.POST("/password/forgot", withOptionalLimit(cfg.PasswordLimit, c.ForgotPassword)...)
		auth.POST("/password/reset", withOptionalLimit(cfg.PasswordLimit, c.ResetPassword)...)

		// JWT-protected endpoints
		protected := auth.Group("")
		protected.Use(cfg.JWTAuth)
		{
			protected.POST("/logout", c.Logout)
			protected.GET("/session", c.GetSession)

			// Session management (JWT + optional rate limiting)
			protected.GET("/sessions", withOptionalLimit(cfg.SessionLimit, c.ListSessions)...)
			protected.DELETE("/sessions/:id", withOptionalLimit(cfg.SessionLimit, c.RevokeSession)...)

			// Verification endpoints (require JWT)
			protected.POST("/verify/send", withOptionalLimit(cfg.VerifyLimit, c.SendVerification)...)
			protected.POST("/verify/confirm", withOptionalLimit(cfg.VerifyLimit, c.ConfirmVerification)...)

			// MFA management (requires JWT + optional rate limiting)
			protected.POST("/mfa/enroll", withOptionalLimit(cfg.MFALimit, c.MFAEnroll)...)
			protected.POST("/mfa/activate", withOptionalLimit(cfg.MFALimit, c.MFAActivate)...)
			protected.DELETE("/mfa", withOptionalLimit(cfg.MFALimit, c.MFADisable)...)
			protected.POST("/mfa/backup-codes", withOptionalLimit(cfg.MFALimit, c.MFAGenerateBackupCodes)...)
		}
	}
}

// LoginRequest login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required,max=254"`
	Password string `json:"password" binding:"required,max=72"`
}

// Login POST /api/auth/login
func (c *AuthController) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	result, err := c.authSvc.LoginByUsernamePassword(ctx, &authService.LoginCommand{
		Username:  req.Username,
		Password:  req.Password,
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
	if err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, loginErrorMap,
			http.StatusUnauthorized, "Login failed")
		return
	}

	if result.RequiresMFA {
		controllerutil.SetNoCacheHeaders(ctx)
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(mfaRequiredResponse(result.MFAToken, result.MFATypes)))
		return
	}

	// Prevent caching of responses containing tokens
	controllerutil.SetNoCacheHeaders(ctx)

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

// RefreshTokenRequest refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,max=128"`
}

// Refresh POST /api/auth/refresh
func (c *AuthController) Refresh(ctx *gin.Context) {
	var req RefreshTokenRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	result, err := c.authSvc.RefreshTokens(ctx, req.RefreshToken)
	if err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, refreshErrorMap,
			http.StatusUnauthorized, "Token refresh failed")
		return
	}

	// Prevent caching of responses containing tokens
	controllerutil.SetNoCacheHeaders(ctx)

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.SessionID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

// MFAVerifyRequest MFA verification request body
type MFAVerifyRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"max=32"`
	Type     string `json:"type"` // "totp" (default) or "passkey"
}

// MFAVerify POST /api/auth/mfa/verify
func (c *AuthController) MFAVerify(ctx *gin.Context) {
	var req MFAVerifyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	// Default empty type to "totp"
	if req.Type == "" {
		req.Type = "totp"
	}

	if req.Type != "totp" && req.Type != "passkey" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "unsupported mfa type"))
		return
	}
	if req.Type != "passkey" && req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "code is required"))
		return
	}

	result, err := c.authSvc.VerifyMFALogin(ctx, req.MFAToken, req.Code, req.Type, ctx.ClientIP(), ctx.Request.UserAgent())
	if err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, mfaVerifyErrorMap,
			http.StatusUnauthorized, "MFA verification failed")
		return
	}

	// Prevent caching of responses containing tokens
	controllerutil.SetNoCacheHeaders(ctx)

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}
