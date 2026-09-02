package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	gossoMiddleware "github.com/rushairer/gosso/middleware"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
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
	MarkSessionStrongAuth(ctx context.Context, sessionID string, methods []string) (*sessionDomain.Session, error)
	ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error)
	RevokeSession(ctx context.Context, accountID, sessionID string) error
	ConfirmVerificationCredential(ctx context.Context, credType, identifier, accountID string) error
	VerifyCurrentPassword(ctx context.Context, accountID, password string) error
	ChangePassword(ctx context.Context, accountID, oldPassword, newPassword string) error
	UpdateProfile(ctx context.Context, accountID string, displayName string) (*accountDomain.Account, error)
	UpdateEmail(ctx context.Context, accountID string, newEmail string) error
	IsEmailAvailable(ctx context.Context, email string) (bool, error)
	MFAService() *authService.MFAService
	PasskeyService() *authService.PasskeyService
}

// BackchannelLogoutNotifier notifies registered OIDC clients of session termination.
type BackchannelLogoutNotifier interface {
	TriggerBackChannelLogout(ctx context.Context, accountID, sessionID string)
}

// AuthController authentication controller
type AuthController struct {
	authSvc             authServiceDeps
	tokenMgr            authService.TokenManager
	socialSvc           *authService.SocialLoginService
	verificationSvc     *authService.VerificationService
	passwordResetSvc    *authService.PasswordResetService
	backchannelNotifier BackchannelLogoutNotifier
	secureCookie        bool
	logger              *zap.Logger
	auditor             *auditService.Auditor
}

// SetAuditor enables durable security-event auditing for compatibility MFA operations.
func (c *AuthController) SetAuditor(auditor *auditService.Auditor) { c.auditor = auditor }

func (c *AuthController) auditMFAStepUp(ctx *gin.Context, accountID, result, reason string) {
	resource, _ := json.Marshal(map[string]string{"session_id": utility.MaskOpaqueID(sessionIDFromClaims(ctx))})
	meta, _ := json.Marshal(map[string]string{"result": result, "reason": reason, "ip": ctx.ClientIP()})
	action := auditDomain.ActionMFAStepUpSuccess
	if result != "success" {
		action = auditDomain.ActionMFAStepUpFailure
	}
	_ = auditService.AuditLogSync(ctx, c.auditor, c.logger, auditDomain.NewRecord(action, "account", &accountID, resource, meta))
}

func sessionIDFromClaims(ctx *gin.Context) string {
	claims, ok := ctx.Get(gossoMiddleware.ContextKeyClaims)
	if !ok {
		return ""
	}
	tc, ok := claims.(*tokenDomain.AccessTokenClaims)
	if !ok {
		return ""
	}
	return tc.SessionID
}

// SetBackchannelLogoutNotifier injects the backchannel logout notifier.
func (c *AuthController) SetBackchannelLogoutNotifier(notifier BackchannelLogoutNotifier) {
	c.backchannelNotifier = notifier
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
	JWTAuth         gin.HandlerFunc   // JWT authentication middleware for protected endpoints
	LoginLimit      gin.HandlerFunc   // Rate limiter for login
	MFALimit        gin.HandlerFunc   // Rate limiter for MFA operations
	MFAStepUpLimits []gin.HandlerFunc // Additional account/session limits for compatibility step-up
	PasswordLimit   gin.HandlerFunc   // Rate limiter for password operations
	RefreshLimit    gin.HandlerFunc   // Rate limiter for token refresh
	VerifyLimit     gin.HandlerFunc   // Rate limiter for verification
	SocialLimit     gin.HandlerFunc   // Rate limiter for social login
	SessionLimit    gin.HandlerFunc   // Rate limiter for session management
}

// RegisterRoutes registers authentication routes.
// All fields in cfg must be non-nil; the method panics on misconfiguration
// so that a missing rate-limit middleware is caught at startup rather than
// silently leaving a security-sensitive endpoint unprotected.
func (c *AuthController) RegisterRoutes(rg *gin.RouterGroup, cfg AuthRouteConfig) {
	if cfg.LoginLimit == nil || cfg.MFALimit == nil || cfg.PasswordLimit == nil ||
		cfg.RefreshLimit == nil || cfg.SocialLimit == nil {
		panic("auth: all rate-limit middleware in AuthRouteConfig must be non-nil")
	}

	auth := rg.Group("/auth")
	{
		auth.POST("/login", cfg.LoginLimit, c.Login)
		auth.POST("/refresh", cfg.RefreshLimit, c.Refresh)

		// MFA verify uses mfa_token, not JWT
		auth.POST("/mfa/verify", cfg.MFALimit, c.MFAVerify)

		// Social login endpoints (unauthenticated)
		auth.GET("/social/:provider", cfg.SocialLimit, c.SocialAuthURL)
		auth.GET("/social/:provider/callback", cfg.SocialLimit, c.SocialCallback)

		// Password reset endpoints (unauthenticated)
		auth.POST("/password/forgot", cfg.PasswordLimit, c.ForgotPassword)
		auth.POST("/password/reset", cfg.PasswordLimit, c.ResetPassword)

		// JWT-protected endpoints
		protected := auth.Group("")
		protected.Use(cfg.JWTAuth)
		{
			protected.POST("/logout", c.Logout)
			protected.GET("/session", c.GetSession)
			protected.POST("/password/change", withOptionalLimit(cfg.PasswordLimit, c.ChangePassword)...)
			protected.PUT("/profile", c.UpdateProfile)
			protected.POST("/profile/email/change/request", withOptionalLimit(cfg.VerifyLimit, c.RequestEmailChange)...)
			protected.POST("/profile/email/change/confirm", withOptionalLimit(cfg.VerifyLimit, c.ConfirmEmailChange)...)

			// Session management (JWT + optional rate limiting)
			protected.GET("/sessions", withOptionalLimit(cfg.SessionLimit, c.ListSessions)...)
			protected.DELETE("/sessions/:id", withOptionalLimit(cfg.SessionLimit, c.RevokeSession)...)

			// Verification endpoints (require JWT)
			protected.POST("/verify/send", withOptionalLimit(cfg.VerifyLimit, c.SendVerification)...)
			protected.POST("/verify/confirm", withOptionalLimit(cfg.VerifyLimit, c.ConfirmVerification)...)

			// MFA management (requires JWT + optional rate limiting)
			protected.GET("/mfa", withOptionalLimit(cfg.MFALimit, c.MFAStatus)...)
			protected.POST("/mfa/enroll", withOptionalLimit(cfg.MFALimit, c.MFAEnroll)...)
			protected.POST("/mfa/activate", withOptionalLimit(cfg.MFALimit, c.MFAActivate)...)
			protected.DELETE("/mfa", withOptionalLimit(cfg.MFALimit, c.MFADisable)...)
			protected.POST("/mfa/backup-codes", withOptionalLimit(cfg.MFALimit, c.MFAGenerateBackupCodes)...)
			stepUpHandlers := make([]gin.HandlerFunc, 0, 2+len(cfg.MFAStepUpLimits))
			stepUpHandlers = append(stepUpHandlers, cfg.MFALimit)
			stepUpHandlers = append(stepUpHandlers, cfg.MFAStepUpLimits...)
			stepUpHandlers = append(stepUpHandlers, c.MFAStepUp)
			protected.POST("/mfa/step-up", stepUpHandlers...)
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
	setSSOSessionCookie(ctx, result.Session.ID, int(c.tokenMgr.RefreshExpiry().Seconds()), c.secureCookie)
	respondTokenSet(ctx, c.tokenMgr, result.AccessToken, result.RefreshToken, result.Session.ID)
}

// RefreshTokenRequest refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"max=128"`
}

// Refresh POST /api/auth/refresh
func (c *AuthController) Refresh(ctx *gin.Context) {
	var req RefreshTokenRequest
	if err := ctx.ShouldBindJSON(&req); err != nil && ctx.Request.ContentLength > 0 {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}
	if req.RefreshToken == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "refresh token is required"))
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
	setSSOSessionCookie(ctx, result.SessionID, int(c.tokenMgr.RefreshExpiry().Seconds()), c.secureCookie)
	respondTokenSet(ctx, c.tokenMgr, result.AccessToken, result.RefreshToken, result.SessionID)
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
	setSSOSessionCookie(ctx, result.Session.ID, int(c.tokenMgr.RefreshExpiry().Seconds()), c.secureCookie)
	respondTokenSet(ctx, c.tokenMgr, result.AccessToken, result.RefreshToken, result.Session.ID)
}

func respondTokenSet(ctx *gin.Context, tokenMgr authService.TokenManager, accessToken, refreshToken, sessionID string) {
	expiresIn := int(tokenMgr.AccessExpiry().Seconds())
	if isCookieSessionRequest(ctx) {
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(cookieSessionResponse(sessionID, expiresIn)))
		return
	}
	// SPA browser requests (with Origin header but without the explicit
	// cookie-session header) must not receive bearer tokens in the response
	// body. Only programmatic API clients (no Origin) get the full token set.
	if isBrowserRequest(ctx) {
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(cookieSessionResponse(sessionID, expiresIn)))
		return
	}
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(accessToken, refreshToken, sessionID, expiresIn)))
}

// isBrowserRequest detects whether the request originates from a browser
// (indicated by the presence of an Origin or Sec-Fetch-Mode: cors header).
// Such requests must not receive bearer tokens in response bodies.
func isBrowserRequest(ctx *gin.Context) bool {
	return ctx.GetHeader("Origin") != "" || ctx.GetHeader("Sec-Fetch-Mode") == "cors"
}
