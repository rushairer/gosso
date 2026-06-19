package controller

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/mail"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	utility "github.com/rushairer/gosso/internal/utility"
	"github.com/rushairer/gosso/middleware"
)

// loginErrorMap maps login service errors to HTTP responses.
var loginErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrServiceUnavailable, Mapping: controllerutil.ErrorMapping{Status: http.StatusServiceUnavailable, Message: "service temporarily unavailable"}},
	{Sentinel: authService.ErrIPLocked, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many attempts from this IP, try again later"}},
	{Sentinel: authService.ErrMFARateLimited, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many MFA attempts, try again later"}},
}

// validSocialProviders is the allowlist of supported social login providers.
var validSocialProviders = map[string]bool{
	"google": true,
	"github": true,
	"wechat": true,
}

// revokeSessionErrorMap maps session revocation errors to HTTP responses.
var revokeSessionErrorMap = []controllerutil.ErrorRule{
	{Sentinel: sessionService.ErrSessionAccessDenied, Mapping: controllerutil.ErrorMapping{Status: http.StatusForbidden, Message: "session not found or access denied"}},
}

// sendVerificationErrorMap maps verification code send errors to HTTP responses.
var sendVerificationErrorMap = []controllerutil.ErrorRule{
	{Sentinel: authService.ErrCooldownActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusTooManyRequests, Message: "too many requests, please try again later"}},
	{Sentinel: authService.ErrUnsupportedType, Mapping: controllerutil.ErrorMapping{Status: http.StatusBadRequest, Message: "unsupported credential type"}},
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
	LoginByUsernamePassword(ctx context.Context, req *authService.LoginRequest) (*authService.LoginResult, error)
	VerifyMFALogin(ctx context.Context, mfaToken, mfaCode, mfaType, ip, userAgent string) (*authService.LoginResult, error)
	Logout(ctx context.Context, accountID, sessionID string, accessTokenJTI string, tokenExpiresAt time.Time) error
	RefreshTokens(ctx context.Context, refreshToken string) (*authService.RefreshResult, error)
	ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error)
	ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error)
	RevokeSession(ctx context.Context, accountID, sessionID string) error
	ConfirmVerificationCredential(ctx context.Context, credType, identifier, accountID string) error
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

// getClaimsFromContext extracts and validates JWT claims from gin.Context
func getClaimsFromContext(ctx *gin.Context) (*tokenDomain.AccessTokenClaims, bool) {
	jwtClaims, exists := ctx.Get(middleware.ContextKeyClaims)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "authentication required"))
		return nil, false
	}
	tc, ok := jwtClaims.(*tokenDomain.AccessTokenClaims)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "invalid claims type"))
		return nil, false
	}
	return tc, true
}

// tokenResponse constructs the standard OAuth2 token response body.
func tokenResponse(accessToken, refreshToken, sessionID string, expiresIn int) gin.H {
	return gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"session_id":    sessionID,
	}
}

// mfaRequiredResponse constructs the MFA-required response body.
func mfaRequiredResponse(token string, mfaTypes []string) gin.H {
	return gin.H{
		"requires_mfa":   true,
		"mfa_token":      token,
		"mfa_token_type": "Bearer",
		"mfa_types":      mfaTypes,
	}
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
		loginHandlers := []gin.HandlerFunc{c.Login}
		if cfg.LoginLimit != nil {
			loginHandlers = []gin.HandlerFunc{cfg.LoginLimit, c.Login}
		}
		auth.POST("/login", loginHandlers...)

		refreshHandlers := []gin.HandlerFunc{c.Refresh}
		if cfg.RefreshLimit != nil {
			refreshHandlers = []gin.HandlerFunc{cfg.RefreshLimit, c.Refresh}
		}
		auth.POST("/refresh", refreshHandlers...)

		// MFA verify uses mfa_token, not JWT
		mfaVerifyHandlers := []gin.HandlerFunc{c.MFAVerify}
		if cfg.MFALimit != nil {
			mfaVerifyHandlers = []gin.HandlerFunc{cfg.MFALimit, c.MFAVerify}
		}
		auth.POST("/mfa/verify", mfaVerifyHandlers...)

		// Social login endpoints (unauthenticated)
		socialHandlers := []gin.HandlerFunc{c.SocialAuthURL}
		if cfg.SocialLimit != nil {
			socialHandlers = []gin.HandlerFunc{cfg.SocialLimit, c.SocialAuthURL}
		}
		auth.GET("/social/:provider", socialHandlers...)
		socialCallbackHandlers := []gin.HandlerFunc{c.SocialCallback}
		if cfg.SocialLimit != nil {
			socialCallbackHandlers = []gin.HandlerFunc{cfg.SocialLimit, c.SocialCallback}
		}
		auth.GET("/social/:provider/callback", socialCallbackHandlers...)

		// Password reset endpoints (unauthenticated)
		passwordHandlers := []gin.HandlerFunc{c.ForgotPassword}
		if cfg.PasswordLimit != nil {
			passwordHandlers = []gin.HandlerFunc{cfg.PasswordLimit, c.ForgotPassword}
		}
		auth.POST("/password/forgot", passwordHandlers...)
		resetPasswordHandlers := []gin.HandlerFunc{c.ResetPassword}
		if cfg.PasswordLimit != nil {
			resetPasswordHandlers = []gin.HandlerFunc{cfg.PasswordLimit, c.ResetPassword}
		}
		auth.POST("/password/reset", resetPasswordHandlers...)

		// JWT-protected endpoints
		protected := auth.Group("")
		protected.Use(cfg.JWTAuth)
		{
			protected.POST("/logout", c.Logout)
			protected.GET("/session", c.GetSession)

			// Session management (JWT + optional rate limiting)
			sessionMgmtHandlers := func() []gin.HandlerFunc {
				if cfg.SessionLimit != nil {
					return []gin.HandlerFunc{cfg.SessionLimit}
				}
				return nil
			}
			protected.GET("/sessions", append(sessionMgmtHandlers(), c.ListSessions)...)
			protected.DELETE("/sessions/:id", append(sessionMgmtHandlers(), c.RevokeSession)...)

			// Verification endpoints (require JWT)
			verifyHandlers := []gin.HandlerFunc{c.SendVerification}
			if cfg.VerifyLimit != nil {
				verifyHandlers = []gin.HandlerFunc{cfg.VerifyLimit, c.SendVerification}
			}
			protected.POST("/verify/send", verifyHandlers...)
			confirmHandlers := []gin.HandlerFunc{c.ConfirmVerification}
			if cfg.VerifyLimit != nil {
				confirmHandlers = []gin.HandlerFunc{cfg.VerifyLimit, c.ConfirmVerification}
			}
			protected.POST("/verify/confirm", confirmHandlers...)

			// MFA management (requires JWT + optional rate limiting)
			protected.POST("/mfa/enroll", append(mfaMgmtHandlers(cfg.MFALimit), c.MFAEnroll)...)
			protected.POST("/mfa/activate", append(mfaMgmtHandlers(cfg.MFALimit), c.MFAActivate)...)
			protected.DELETE("/mfa", append(mfaMgmtHandlers(cfg.MFALimit), c.MFADisable)...)
			protected.POST("/mfa/backup-codes", append(mfaMgmtHandlers(cfg.MFALimit), c.MFAGenerateBackupCodes)...)
		}
	}
}

// mfaMgmtHandlers returns rate limit middleware for MFA management endpoints, or nil if no limit.
func mfaMgmtHandlers(mfaLimit gin.HandlerFunc) []gin.HandlerFunc {
	if mfaLimit == nil {
		return nil
	}
	return []gin.HandlerFunc{mfaLimit}
}

// LoginRequest login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required,max=255"`
	Password string `json:"password" binding:"required,max=128"`
}

// Login POST /api/auth/login
func (c *AuthController) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	result, err := c.authSvc.LoginByUsernamePassword(ctx, &authService.LoginRequest{
		Username:  req.Username,
		Password:  req.Password,
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
	if err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, loginErrorMap,
			http.StatusUnauthorized, "Login failed")
		return
	}

	if result.RequiresMFA {
		controllerutil.SetNoCacheHeaders(ctx)
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(mfaRequiredResponse(result.AccessToken, result.MFATypes)))
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
	RefreshToken string `json:"refresh_token" binding:"required,max=2048"`
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
		controllerutil.HandleServiceError(ctx, c.logger, err, refreshErrorMap,
			http.StatusUnauthorized, "Token refresh failed")
		return
	}

	// Prevent caching of responses containing tokens
	controllerutil.SetNoCacheHeaders(ctx)

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.SessionID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

// Logout POST /api/auth/logout
func (c *AuthController) Logout(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	accessTokenJTI := tc.ID
	var tokenExpiresAt time.Time
	if tc.ExpiresAt != nil {
		tokenExpiresAt = tc.ExpiresAt.Time
	}

	if err := c.authSvc.Logout(ctx, tc.AccountID, tc.SessionID, accessTokenJTI, tokenExpiresAt); err != nil {
		c.logger.Error("Logout error", zap.String("account_id", utility.MaskOpaqueID(tc.AccountID)), zap.String("session_id", utility.MaskOpaqueID(tc.SessionID)), zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout incomplete"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("logged out"))
}

// GetSession GET /api/auth/session
func (c *AuthController) GetSession(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	session, err := c.authSvc.ValidateSession(ctx, tc.SessionID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "session invalid"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(session))
}

// ListSessions GET /api/auth/sessions
func (c *AuthController) ListSessions(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	sessions, err := c.authSvc.ListSessions(ctx, tc.AccountID)
	if err != nil {
		c.logger.Error("Failed to list sessions", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to list sessions"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(sessions))
}

// RevokeSession DELETE /api/auth/sessions/:id
func (c *AuthController) RevokeSession(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	sessionID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("id"), "session_id")
	if !ok {
		return
	}

	// Do not allow revoking the current session (should use logout)
	if sessionID == tc.SessionID {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "use /logout to revoke current session"))
		return
	}

	if err := c.authSvc.RevokeSession(ctx, tc.AccountID, sessionID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, revokeSessionErrorMap,
			http.StatusInternalServerError, "Failed to revoke session")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"revoked": true}))
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

	if req.Type != "passkey" && req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "code is required"))
		return
	}
	if req.Type != "" && req.Type != "totp" && req.Type != "passkey" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "unsupported mfa type"))
		return
	}

	result, err := c.authSvc.VerifyMFALogin(ctx, req.MFAToken, req.Code, req.Type, ctx.ClientIP(), ctx.Request.UserAgent())
	if err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, mfaVerifyErrorMap,
			http.StatusUnauthorized, "MFA verification failed")
		return
	}

	// Prevent caching of responses containing tokens
	controllerutil.SetNoCacheHeaders(ctx)

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

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
		c.logger.Error("MFA enrollment failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to enroll MFA"))
		return
	}

	controllerutil.SetNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(enrollment))
}

// MFAActivateRequest MFA activation request body
type MFAActivateRequest struct {
	Code string `json:"code" binding:"required"`
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

// MFADisable DELETE /api/auth/mfa
func (c *AuthController) MFADisable(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	mfaSvc := c.authSvc.MFAService()
	if mfaSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "MFA service not available"))
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

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"backup_codes": codes,
	}))
}

// SocialAuthURL GET /api/auth/social/:provider
func (c *AuthController) SocialAuthURL(ctx *gin.Context) {
	if c.socialSvc == nil {
		ctx.JSON(http.StatusNotImplemented, gouno.NewErrorResponse(http.StatusNotImplemented, "social login not configured"))
		return
	}

	provider := ctx.Param("provider")
	if !validSocialProviders[provider] {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "unsupported social provider"))
		return
	}

	// Generate cryptographic state for CSRF protection
	state, err := authService.GenerateAuthState()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to generate state"))
		return
	}
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/api/auth/social",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   c.secureCookie,
		// Lax is required here: the OAuth callback is a cross-site redirect from
		// the provider, so Strict would drop the cookie. Lax allows top-level
		// navigations while still blocking embedded cross-site requests.
		SameSite: http.SameSiteLaxMode,
	})

	authURL, err := c.socialSvc.GetAuthURL(ctx, provider, state)
	if err != nil {
		c.logger.Warn("Social auth URL generation failed", zap.String("provider", provider), zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "social login not available"))
		return
	}

	ctx.Redirect(http.StatusFound, authURL)
}

// SocialCallback GET /api/auth/social/:provider/callback
func (c *AuthController) SocialCallback(ctx *gin.Context) {
	if c.socialSvc == nil {
		ctx.JSON(http.StatusNotImplemented, gouno.NewErrorResponse(http.StatusNotImplemented, "social login not configured"))
		return
	}

	// Validate state parameter (CSRF protection)
	state := ctx.Query("state")
	savedState, _ := ctx.Cookie("oauth_state")
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/api/auth/social",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	if state == "" || savedState == "" || subtle.ConstantTimeCompare([]byte(state), []byte(savedState)) != 1 {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid or missing state parameter"))
		return
	}

	provider := ctx.Param("provider")
	if !validSocialProviders[provider] {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "unsupported social provider"))
		return
	}
	code := ctx.Query("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "missing code parameter"))
		return
	}
	if len(code) > 4096 {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "code parameter too long"))
		return
	}

	result, err := c.socialSvc.HandleCallback(ctx, provider, code, ctx.ClientIP(), ctx.Request.UserAgent())
	if err != nil {
		c.logger.Warn("Social login callback failed", zap.String("provider", provider), zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "social login failed"))
		return
	}

	// Prevent caching of responses containing tokens
	controllerutil.SetNoCacheHeaders(ctx)

	if result.RequiresMFA {
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(mfaRequiredResponse(result.AccessToken, result.MFATypes)))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
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
	credType := accountDomain.CredentialTypeEmail
	if req.Type == "phone" {
		credType = accountDomain.CredentialTypePhone
	}
	if err := c.verificationSvc.ValidateCredentialOwnership(ctx, tc.AccountID, string(credType), req.Identifier); err != nil {
		c.logger.Warn("Credential ownership validation failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	if err := c.verificationSvc.SendCode(ctx, req.Type, req.Identifier, tc.AccountID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, sendVerificationErrorMap,
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
		c.logger.Warn("Password reset request failed", zap.String("email", utility.MaskEmail(req.Email)), zap.Error(err))
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
