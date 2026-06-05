package controller

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	authService "github.com/rushairer/gosso/internal/auth/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/utility"
)

// AuthController authentication controller
type AuthController struct {
	authSvc          authService.AuthOrchestrator
	tokenMgr         authService.TokenManager
	socialSvc        *authService.SocialLoginService
	verificationSvc  *authService.VerificationService
	passwordResetSvc *authService.PasswordResetService
	credentialRepo   accountRepo.CredentialRepository
	db               *sql.DB
	secureCookie     bool
	logger           *zap.Logger
}

// getClaimsFromContext extracts and validates JWT claims from gin.Context
func getClaimsFromContext(ctx *gin.Context) (*tokenDomain.AccessTokenClaims, bool) {
	jwtClaims, exists := ctx.Get("jwt_claims")
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

// NewAuthController creates a new instance of AuthController
func NewAuthController(
	authSvc authService.AuthOrchestrator,
	tokenMgr authService.TokenManager,
	socialSvc *authService.SocialLoginService,
	verificationSvc *authService.VerificationService,
	passwordResetSvc *authService.PasswordResetService,
	credentialRepo accountRepo.CredentialRepository,
	db *sql.DB,
	secureCookie bool,
	logger *zap.Logger,
) *AuthController {
	return &AuthController{
		authSvc:          authSvc,
		tokenMgr:         tokenMgr,
		socialSvc:        socialSvc,
		verificationSvc:  verificationSvc,
		passwordResetSvc: passwordResetSvc,
		credentialRepo:   credentialRepo,
		db:               db,
		secureCookie:     secureCookie,
		logger:           logger,
	}
}

// RegisterRoutes registers authentication routes
// jwtAuth: JWT authentication middleware for protected endpoints
// loginLimit, mfaLimit, passwordLimit, refreshLimit, verifyLimit, socialLimit: optional per-endpoint rate limiting middlewares
func (c *AuthController) RegisterRoutes(rg *gin.RouterGroup, jwtAuth gin.HandlerFunc, loginLimit gin.HandlerFunc, mfaLimit gin.HandlerFunc, passwordLimit gin.HandlerFunc, refreshLimit gin.HandlerFunc, verifyLimit gin.HandlerFunc, socialLimit ...gin.HandlerFunc) {
	auth := rg.Group("/auth")
	{
		loginHandlers := []gin.HandlerFunc{c.Login}
		if loginLimit != nil {
			loginHandlers = []gin.HandlerFunc{loginLimit, c.Login}
		}
		auth.POST("/login", loginHandlers...)

		refreshHandlers := []gin.HandlerFunc{c.Refresh}
		if refreshLimit != nil {
			refreshHandlers = []gin.HandlerFunc{refreshLimit, c.Refresh}
		}
		auth.POST("/refresh", refreshHandlers...)

		// MFA verify uses mfa_token, not JWT
		mfaVerifyHandlers := []gin.HandlerFunc{c.MFAVerify}
		if mfaLimit != nil {
			mfaVerifyHandlers = []gin.HandlerFunc{mfaLimit, c.MFAVerify}
		}
		auth.POST("/mfa/verify", mfaVerifyHandlers...)

		// Social login endpoints (unauthenticated)
		auth.GET("/social/:provider", c.SocialAuthURL)
		socialCallbackHandlers := []gin.HandlerFunc{c.SocialCallback}
		if len(socialLimit) > 0 && socialLimit[0] != nil {
			socialCallbackHandlers = []gin.HandlerFunc{socialLimit[0], c.SocialCallback}
		}
		auth.GET("/social/:provider/callback", socialCallbackHandlers...)

		// Verification endpoints (unauthenticated)
		verifyHandlers := []gin.HandlerFunc{c.SendVerification}
		if verifyLimit != nil {
			verifyHandlers = []gin.HandlerFunc{verifyLimit, c.SendVerification}
		}
		auth.POST("/verify/send", verifyHandlers...)
		confirmHandlers := []gin.HandlerFunc{c.ConfirmVerification}
		if verifyLimit != nil {
			confirmHandlers = []gin.HandlerFunc{verifyLimit, c.ConfirmVerification}
		}
		auth.POST("/verify/confirm", confirmHandlers...)

		// Password reset endpoints (unauthenticated)
		passwordHandlers := []gin.HandlerFunc{c.ForgotPassword}
		if passwordLimit != nil {
			passwordHandlers = []gin.HandlerFunc{passwordLimit, c.ForgotPassword}
		}
		auth.POST("/password/forgot", passwordHandlers...)
		resetPasswordHandlers := []gin.HandlerFunc{c.ResetPassword}
		if passwordLimit != nil {
			resetPasswordHandlers = []gin.HandlerFunc{passwordLimit, c.ResetPassword}
		}
		auth.POST("/password/reset", resetPasswordHandlers...)

		// JWT-protected endpoints
		protected := auth.Group("")
		protected.Use(jwtAuth)
		{
			protected.POST("/logout", c.Logout)
			protected.GET("/session", c.GetSession)

			// Session management
			protected.GET("/sessions", c.ListSessions)
			protected.DELETE("/sessions/:id", c.RevokeSession)

			// MFA management (requires JWT + optional rate limiting)
			protected.POST("/mfa/enroll", append(mfaMgmtHandlers(mfaLimit), c.MFAEnroll)...)
			protected.POST("/mfa/activate", append(mfaMgmtHandlers(mfaLimit), c.MFAActivate)...)
			protected.DELETE("/mfa", append(mfaMgmtHandlers(mfaLimit), c.MFADisable)...)
			protected.POST("/mfa/backup-codes", append(mfaMgmtHandlers(mfaLimit), c.MFAGenerateBackupCodes)...)
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

// LoginRequestBody login request body
type LoginRequestBody struct {
	Username string `json:"username" binding:"required,max=255"`
	Password string `json:"password" binding:"required,max=128"`
}

// Login POST /api/auth/login
func (c *AuthController) Login(ctx *gin.Context) {
	var req LoginRequestBody
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
		c.logger.Warn("Login failed", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid credentials"))
		return
	}

	if result.RequiresMFA {
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
			"requires_mfa":   true,
			"mfa_token":      result.AccessToken,
			"mfa_token_type": "Bearer",
			"mfa_types":      result.MFATypes,
		}))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenMgr.AccessExpiry().Seconds()),
		"session_id":    result.Session.ID.String(),
	}))
}

// RefreshTokenRequest refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
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
		c.logger.Warn("Token refresh failed", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid refresh token"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenMgr.AccessExpiry().Seconds()),
		"session_id":    result.SessionID,
	}))
}

// LogoutRequest logout request body
type LogoutRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Logout POST /api/auth/logout
func (c *AuthController) Logout(ctx *gin.Context) {
	jwtClaims, exists := ctx.Get("jwt_claims")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}
	tc, ok := jwtClaims.(*tokenDomain.AccessTokenClaims)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}

	accessTokenJTI := tc.ID
	var tokenExpiresAt time.Time
	if tc.ExpiresAt != nil {
		tokenExpiresAt = tc.ExpiresAt.Time
	}

	if err := c.authSvc.Logout(ctx, tc.AccountID, tc.SessionID, accessTokenJTI, tokenExpiresAt); err != nil {
		c.logger.Error("Logout error", zap.String("account_id", tc.AccountID), zap.String("session_id", tc.SessionID), zap.Error(err))
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

	sessionID := ctx.Param("id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "session id required"))
		return
	}

	// Do not allow revoking the current session (should use logout)
	if sessionID == tc.SessionID {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "use /logout to revoke current session"))
		return
	}

	if err := c.authSvc.RevokeSession(ctx, tc.AccountID, sessionID); err != nil {
		if errors.Is(err, sessionService.ErrSessionAccessDenied) {
			ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "session not found or access denied"))
		} else {
			c.logger.Error("Failed to revoke session", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "internal server error"))
		}
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
		c.logger.Warn("MFA verification failed", zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid or expired MFA token"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenMgr.AccessExpiry().Seconds()),
		"session_id":    result.Session.ID.String(),
	}))
}

// MFAEnroll POST /api/auth/mfa/enroll
func (c *AuthController) MFAEnroll(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	enrollment, err := c.authSvc.MFAService().EnrollTOTP(ctx, tc.AccountID)
	if err != nil {
		c.logger.Error("MFA enrollment failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to enroll MFA"))
		return
	}

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

	if err := c.authSvc.MFAService().ActivateTOTP(ctx, tc.AccountID, req.Code); err != nil {
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

	if err := c.authSvc.MFAService().DisableTOTP(ctx, tc.AccountID); err != nil {
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

	codes, err := c.authSvc.MFAService().GenerateBackupCodes(ctx, tc.AccountID)
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

	// Generate cryptographic state for CSRF protection
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to generate state"))
		return
	}
	state := hex.EncodeToString(stateBytes)
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/api/auth/social",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   c.secureCookie,
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
	code := ctx.Query("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "missing code parameter"))
		return
	}

	result, err := c.socialSvc.HandleCallback(ctx, provider, code, ctx.ClientIP(), ctx.Request.UserAgent())
	if err != nil {
		c.logger.Warn("Social login callback failed", zap.String("provider", provider), zap.Error(err))
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "social login failed"))
		return
	}

	if result.RequiresMFA {
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
			"requires_mfa":   true,
			"mfa_token":      result.AccessToken,
			"mfa_token_type": "Bearer",
			"mfa_types":      result.MFATypes,
		}))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenMgr.AccessExpiry().Seconds()),
		"session_id":    result.Session.ID.String(),
	}))
}

// SendVerificationRequest send verification code request body
type SendVerificationRequest struct {
	Type       string `json:"type" binding:"required"`       // "email" or "phone"
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

	if len(req.Identifier) > 255 {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "identifier too long"))
		return
	}
	if req.Type == "email" && !containsAtSign(req.Identifier) {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid email format"))
		return
	}
	if req.Type == "phone" && !utility.ValidatePhoneFormat(req.Identifier) {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid phone format"))
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
	creds, err := c.credentialRepo.FindByAccountAndType(ctx, tc.AccountID, credType)
	if err != nil {
		c.logger.Error("Failed to lookup credentials for verification", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "verification failed"))
		return
	}
	found := false
	for _, cred := range creds {
		if cred.Identifier != nil && *cred.Identifier == req.Identifier {
			found = true
			break
		}
	}
	if !found {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "identifier not associated with this account"))
		return
	}

	if err := c.verificationSvc.SendCode(ctx, req.Type, req.Identifier, tc.AccountID); err != nil {
		c.logger.Warn("Failed to send verification code", zap.String("type", req.Type), zap.Error(err))
		ctx.JSON(http.StatusTooManyRequests, gouno.NewErrorResponse(http.StatusTooManyRequests, "too many requests, please try again later"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("verification code sent"))
}

// ConfirmVerificationRequest confirm verification code request body
type ConfirmVerificationRequest struct {
	Type       string `json:"type" binding:"required"`
	Identifier string `json:"identifier" binding:"required,max=255"`
	Code       string `json:"code" binding:"required"`
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

	// Validate verification code
	accountID, err := c.verificationSvc.VerifyCode(ctx, req.Type, req.Identifier, req.Code)
	if err != nil {
		c.logger.Warn("Verification code failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid verification code"))
		return
	}

	// The verification code belongs to the current user
	if accountID != tc.AccountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "verification code does not belong to this account"))
		return
	}

	// Find credential and mark it as verified
	var credType accountDomain.CredentialType
	if req.Type == "email" {
		credType = accountDomain.CredentialTypeEmail
	} else {
		credType = accountDomain.CredentialTypePhone
	}

	cred, err := c.credentialRepo.FindByTypeAndIdentifier(ctx, credType, req.Identifier)
	if err != nil {
		c.logger.Warn("Failed to find credential for verification confirmation", zap.Error(err), zap.String("type", req.Type), zap.String("identifier", utility.MaskIdentifier(req.Type, req.Identifier)))
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "credential not found"))
		return
	}

	if cred.AccountID != tc.AccountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "credential does not belong to this account"))
		return
	}

	cred.Verify()
	if err := dbutil.RunInTransaction(ctx, c.db, func(tx *sql.Tx) error {
		return c.credentialRepo.UpdateCredential(ctx, tx, cred)
	}); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to update credential"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("credential verified"))
}

// ForgotPasswordRequestBody forgot password request body
type ForgotPasswordRequestBody struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPassword POST /api/auth/password/forgot
func (c *AuthController) ForgotPassword(ctx *gin.Context) {
	var req ForgotPasswordRequestBody
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if err := c.passwordResetSvc.RequestReset(ctx, req.Email); err != nil {
		c.logger.Warn("Password reset request error", zap.Error(err))
	}

	// Always return 200 to prevent email enumeration
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("if the email exists, a reset link has been sent"))
}

// ResetPasswordRequestBody reset password request body
type ResetPasswordRequestBody struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=128"`
}

// ResetPassword POST /api/auth/password/reset
func (c *AuthController) ResetPassword(ctx *gin.Context) {
	var req ResetPasswordRequestBody
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

// containsAtSign checks if s contains '@' — a minimal email format gate.
func containsAtSign(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}
