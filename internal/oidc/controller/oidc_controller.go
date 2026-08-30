package controller

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountService "github.com/rushairer/gosso/internal/account/service"
	authMiddleware "github.com/rushairer/gosso/internal/auth/middleware"
	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
	"github.com/rushairer/gosso/middleware"
)

// userInfoErrorMap maps user info service errors to HTTP responses.
var userInfoErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrAccountNotActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusForbidden, Message: "account is not active"}},
}

// OIDCController OIDC protocol controller
type OIDCController struct {
	discoverySvc     *oidcService.DiscoveryService
	jwksSvc          *oidcService.JWKSService
	userInfoSvc      *oidcService.UserInfoService
	logoutSvc        *oidcService.LogoutService
	clientRepo       oauth2Repo.OAuth2ClientRepository
	tokenSvc         *tokenService.TokenService
	sessionValidator sessionDomain.SessionValidator
	issuer           string
	logger           *zap.Logger
}

// NewOIDCController creates a new instance of OIDCController
func NewOIDCController(
	discoverySvc *oidcService.DiscoveryService,
	jwksSvc *oidcService.JWKSService,
	userInfoSvc *oidcService.UserInfoService,
	logoutSvc *oidcService.LogoutService,
	clientRepo oauth2Repo.OAuth2ClientRepository,
	tokenSvc *tokenService.TokenService,
	sessionValidator sessionDomain.SessionValidator,
	issuer string,
	logger *zap.Logger,
) *OIDCController {
	return &OIDCController{
		discoverySvc:     discoverySvc,
		jwksSvc:          jwksSvc,
		userInfoSvc:      userInfoSvc,
		logoutSvc:        logoutSvc,
		clientRepo:       clientRepo,
		tokenSvc:         tokenSvc,
		sessionValidator: sessionValidator,
		issuer:           issuer,
		logger:           logger,
	}
}

func (c *OIDCController) RegisterRoutes(server *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	server.GET("/userinfo", authMiddleware, c.UserInfo)
	server.POST("/userinfo", authMiddleware, c.UserInfo)
	server.GET("/logout", c.LogoutConfirm)
	server.POST("/logout", c.Logout)
	server.GET("/frontchannel_logout", c.FrontChannelLogout)
}

// Discovery GET /.well-known/openid-configuration
func (c *OIDCController) Discovery(ctx *gin.Context) {
	ctx.Header("Cache-Control", "public, max-age=3600")
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", c.discoverySvc.GetDiscoveryDocument())
}

// JWKS GET /.well-known/jwks.json
func (c *OIDCController) JWKS(ctx *gin.Context) {
	ctx.Header("Cache-Control", "public, max-age=3600")
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", c.jwksSvc.GetJWKS())
}

// UserInfo GET /oidc/userinfo
func (c *OIDCController) UserInfo(ctx *gin.Context) {
	jwtClaims, exists := ctx.Get(middleware.ContextKeyClaims)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "authentication required"))
		return
	}

	claims, ok := jwtClaims.(*tokenDomain.AccessTokenClaims)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "invalid token"))
		return
	}

	// Parse scope
	scopes := strings.Split(claims.Scope, " ")

	info, err := c.userInfoSvc.GetUserInfo(ctx, claims.AccountID, scopes)
	if err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, userInfoErrorMap,
			http.StatusInternalServerError, "Failed to get user info")
		return
	}
	// Roles are an authorization attribute, not a standard OIDC profile claim.
	// Expose them only to clients that were explicitly granted the trusted admin
	// scope; ordinary OIDC relying parties must not learn internal role data.
	if hasScope(claims.Scope, "admin") {
		info["roles"] = claims.Roles
		info["scope"] = claims.Scope
	}

	ctx.JSON(http.StatusOK, info)
}

func hasScope(scopeClaim, required string) bool {
	for _, scope := range strings.Fields(scopeClaim) {
		if scope == required {
			return true
		}
	}
	return false
}

// logoutRequest holds the parameters for OIDC RP-Initiated Logout.
type logoutRequest struct {
	IDTokenHint           string `form:"id_token_hint"`
	ClientID              string `form:"client_id"`
	PostLogoutRedirectURI string `form:"post_logout_redirect_uri"`
	State                 string `form:"state"`
}

// Logout handles POST /oidc/logout per OpenID Connect RP-Initiated Logout 1.0.
//
// CSRF note: CSRF middleware skips requests with a Bearer Authorization header,
// so if a Bearer token is present it MUST be validated here (not just forwarded).
// An invalid Bearer header is rejected immediately to prevent CSRF bypass via
// a forged Authorization header combined with a stolen id_token_hint.
func (c *OIDCController) Logout(ctx *gin.Context) {
	var req logoutRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	// Security: CSRF middleware skips validation when a Bearer header is present.
	// If the Bearer header is invalid (or a forgery), reject immediately to prevent
	// CSRF bypass via a fake Authorization header combined with a stolen id_token_hint.
	bearerClaims := c.validateBearerToken(ctx)
	if ctx.IsAborted() {
		return
	}

	// CSRF protection for id_token_hint (without Bearer) is handled by CSRFMiddleware
	// applied at the router layer: POST without a Bearer token → CSRF cookie validated.
	// No additional check is needed here — the middleware enforces double-submit cookie
	// validation before this handler runs.

	// Try logout paths in order: id_token_hint → Bearer token → anonymous
	var clientID string
	logoutPerformed := false

	if req.IDTokenHint != "" {
		if cid, ok := c.tryLogoutByIDTokenHint(ctx, req, bearerClaims); ok {
			clientID = cid
			logoutPerformed = true
		}
		if ctx.IsAborted() {
			return
		}
	}

	if clientID == "" && bearerClaims != nil {
		clientID = c.tryLogoutByBearerToken(ctx, bearerClaims)
		// If we had a Bearer token, a logout was performed (or attempted).
		// Even if clientID is empty (no client_id in claims), the user was identified.
		logoutPerformed = true
		if ctx.IsAborted() {
			return
		}
	}

	if clientID == "" && !logoutPerformed {
		if cid, ok := c.tryLogoutByCookieSession(ctx, req); ok {
			clientID = cid
			logoutPerformed = true
		}
	}

	ctx.SetCookie("__Host-gosso-session", "", -1, "/", "", true, true)
	ctx.SetCookie("__Host-access_token", "", -1, "/", "", true, true)
	ctx.SetCookie("__Host-refresh_token", "", -1, "/", "", true, true)
	ctx.SetCookie("__Host-csrf_token", "", -1, "/", "", true, false)
	ctx.SetCookie("access_token", "", -1, "/", "", false, true)
	ctx.SetCookie("refresh_token", "", -1, "/", "", false, true)
	ctx.SetCookie("csrf_token", "", -1, "/", "", false, false)

	// Post-logout redirect
	if req.PostLogoutRedirectURI != "" && clientID != "" {
		c.handlePostLogoutRedirect(ctx, req, clientID)
		return
	}

	if !logoutPerformed {
		// No id_token_hint, no Bearer token, no session cookie — unable to identify the user.
		// Per OIDC RP-Initiated Logout, return 401 rather than a misleading 200.
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized,
			"authentication required"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"status": "logged_out"}))
}

// LogoutConfirm handles GET /oidc/logout — it shows a confirmation page or
// redirects immediately if a valid id_token_hint with sid is present.
// GET must NOT perform state-mutating logout to prevent logout CSRF via
// cross-site top-level navigation. Actual logout is only done via POST.
func (c *OIDCController) LogoutConfirm(ctx *gin.Context) {
	var req logoutRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	// If a valid id_token_hint with sid is provided, we can show the confirmation
	// page with the user identified. Without sid, we show a generic confirmation.
	// In either case, the actual logout is NOT performed on GET.
	if req.IDTokenHint != "" {
		_, err := c.logoutSvc.ValidateIDTokenHint(req.IDTokenHint, req.ClientID)
		if err != nil {
			if errors.Is(err, oidcService.ErrAudienceMismatch) {
				ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
				return
			}
			c.logger.Debug("id_token_hint validation failed on GET logout", zap.Error(err))
		} else {
			// Render a confirmation form that POSTs to /oidc/logout with the same parameters.
			ctx.Header("Content-Type", "text/html; charset=utf-8")
			ctx.Status(http.StatusOK)
			_, _ = ctx.Writer.WriteString(`<!DOCTYPE html>
<html>
<head><title>Confirm Logout</title></head>
<body>
<h1>Confirm Logout</h1>
<p>You are about to log out from the identity provider.</p>
<form method="POST" action="/oidc/logout">` +
				hiddenInput("csrf_token", logoutCSRFTokenFromCookie(ctx)) +
				hiddenInput("id_token_hint", req.IDTokenHint) +
				hiddenInput("client_id", req.ClientID) +
				hiddenInput("post_logout_redirect_uri", req.PostLogoutRedirectURI) +
				hiddenInput("state", req.State) +
				`<button type="submit">Confirm Logout</button>
</form>
</body>
</html>`)
			return
		}
	}

	// No valid id_token_hint — show generic confirmation page.
	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.Status(http.StatusOK)
	_, _ = ctx.Writer.WriteString(`<!DOCTYPE html>
<html>
<head><title>Confirm Logout</title></head>
<body>
<h1>Confirm Logout</h1>
<p>You are about to log out from the identity provider.</p>
<form method="POST" action="/oidc/logout">` +
		hiddenInput("csrf_token", logoutCSRFTokenFromCookie(ctx)) +
		hiddenInput("client_id", req.ClientID) +
		hiddenInput("post_logout_redirect_uri", req.PostLogoutRedirectURI) +
		hiddenInput("state", req.State) +
		`<button type="submit">Confirm Logout</button>
</form>
</body>
</html>`)
}

func logoutCSRFTokenFromCookie(ctx *gin.Context) string {
	cookie, _ := ctx.Cookie("__Host-csrf_token")
	if cookie == "" {
		cookie, _ = ctx.Cookie("csrf_token")
	}
	return cookie
}

// hiddenInput renders a hidden <input> element with HTML-escaped value.
func hiddenInput(name, value string) string {
	return `<input type="hidden" name="` + html.EscapeString(name) +
		`" value="` + html.EscapeString(value) + `">`
}

// validateBearerToken validates the Bearer token from the Authorization header.
// Returns nil if no Bearer header is present. Aborts the request if the token is invalid.
func (c *OIDCController) validateBearerToken(ctx *gin.Context) *tokenDomain.AccessTokenClaims {
	if ctx.GetHeader("Authorization") == "" {
		return nil
	}
	claims, err := authMiddleware.ValidateBearerToken(ctx, c.tokenSvc, c.sessionValidator)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid session"))
		ctx.Abort()
		return nil
	}
	return claims
}

// tryLogoutByCookieSession attempts logout using the OP cookie session.
// It first checks for the opaque SSO session cookie, falling back to
// legacy token cookies for backward compatibility.
func (c *OIDCController) tryLogoutByCookieSession(ctx *gin.Context, req logoutRequest) (string, bool) {
	// Primary path: opaque SSO session cookie (new approach).
	if sid, err := ctx.Cookie("__Host-gosso-session"); err == nil && sid != "" {
		if c.sessionValidator != nil {
			session, valErr := c.sessionValidator.ValidateSession(ctx.Request.Context(), sid)
			if valErr != nil {
				return "", false
			}
			_ = c.logoutSvc.LogoutBySessionID(ctx.Request.Context(), session.AccountID, sid)
			return req.ClientID, true
		}
	}

	// Legacy fallback: token cookie (for clients still using old cookies).
	cookieToken := ""
	if cookie, err := ctx.Cookie("__Host-access_token"); err == nil && cookie != "" {
		cookieToken = cookie
	} else if cookie, err := ctx.Cookie("access_token"); err == nil && cookie != "" {
		cookieToken = cookie
	}
	if cookieToken == "" {
		return "", false
	}
	claims, err := c.tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), cookieToken)
	if err != nil {
		return "", false
	}
	if c.sessionValidator != nil && claims.SessionID != "" {
		if _, valErr := c.sessionValidator.ValidateSession(ctx.Request.Context(), claims.SessionID); valErr != nil {
			return "", false
		}
	}
	if claims.SessionID != "" {
		_ = c.logoutSvc.LogoutBySessionID(ctx.Request.Context(), claims.AccountID, claims.SessionID)
	} else {
		c.logger.Debug("Cookie session has no sid, skipping server-side session logout",
			zap.String("account_id", utility.MaskOpaqueID(claims.AccountID)))
	}
	if claims.ExpiresAt != nil {
		_ = c.tokenSvc.RevokeAccessToken(ctx.Request.Context(), claims.ID, claims.ExpiresAt.Time)
	}
	clientID := req.ClientID
	if clientID == "" {
		clientID = claims.ClientID
	}
	return clientID, true
}

// tryLogoutByIDTokenHint attempts logout using the id_token_hint parameter.
// Returns the resolved clientID and true on success, or ("", false) to fall through.
func (c *OIDCController) tryLogoutByIDTokenHint(ctx *gin.Context, req logoutRequest, bearerClaims *tokenDomain.AccessTokenClaims) (string, bool) {
	claims, err := c.logoutSvc.ValidateIDTokenHint(req.IDTokenHint, req.ClientID)
	if err != nil {
		// Audience mismatch is a client error — return 400 instead of falling through.
		if errors.Is(err, oidcService.ErrAudienceMismatch) {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			ctx.Abort()
			return "", true // handled (with error)
		}
		c.logger.Debug("id_token_hint validation failed, skipping", zap.Error(err))
		return "", false
	}

	accountID := claims.Subject

	// When both id_token_hint and Bearer token are present, verify identity match
	if bearerClaims != nil && bearerClaims.AccountID != accountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden,
			"id_token_hint subject does not match authenticated user"))
		ctx.Abort()
		return "", true // handled (with error)
	}

	var logoutErr error
	if claims.SID != "" {
		// New token with sid — logout only this session.
		logoutErr = c.logoutSvc.LogoutBySessionID(ctx, accountID, claims.SID)
	} else {
		// Legacy token without sid — try to identify the current OP session
		// from the cookie and logout only that session, rather than all
		// sessions for the account (which is the "logout all devices" feature).
		cookieToken := ""
		if cookie, err := ctx.Cookie("__Host-access_token"); err == nil && cookie != "" {
			cookieToken = cookie
		} else if cookie, err := ctx.Cookie("access_token"); err == nil && cookie != "" {
			cookieToken = cookie
		}
		if cookieToken != "" {
			cookieClaims, cookieErr := c.tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), cookieToken)
			if cookieErr == nil && cookieClaims.AccountID == accountID && cookieClaims.SessionID != "" {
				// Found a valid current session for the same account — logout only it.
				logoutErr = c.logoutSvc.LogoutBySessionID(ctx, accountID, cookieClaims.SessionID)
			} else if cookieErr == nil && cookieClaims.AccountID == accountID && c.sessionValidator != nil {
				if _, valErr := c.sessionValidator.ValidateSession(ctx.Request.Context(), cookieClaims.SessionID); valErr == nil {
					logoutErr = c.logoutSvc.LogoutBySessionID(ctx, accountID, cookieClaims.SessionID)
				}
			}
		}
		if logoutErr == nil && cookieToken == "" {
			// No OP cookie session available — cannot determine which session
			// to logout. Do NOT fall back to LogoutByAccountID (which would
			// revoke all sessions). Instead, proceed without error; the caller
			// will still clear browser cookies and redirect.
			c.logger.Debug("id_token_hint without sid: no OP cookie session found, skipping server-side session logout",
				zap.String("account_id", utility.MaskOpaqueID(accountID)))
		}
	}
	if logoutErr != nil {
		c.logger.Error("Logout by session/account failed", zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(logoutErr))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
		ctx.Abort()
		return "", true
	}

	// Blacklist the current access token if a Bearer header was also provided
	if bearerClaims != nil && bearerClaims.ExpiresAt != nil {
		if err := c.tokenSvc.RevokeAccessToken(ctx, bearerClaims.ID, bearerClaims.ExpiresAt.Time); err != nil {
			c.logger.Warn("Failed to blacklist access token during id_token_hint logout",
				zap.String("jti", utility.MaskOpaqueID(bearerClaims.ID)), zap.Error(err))
		}
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	if req.ClientID != "" {
		clientID = req.ClientID
	}
	return clientID, true
}

// tryLogoutByBearerToken attempts logout using the validated Bearer token claims.
// Returns the resolved clientID, or "" if no logout was performed.
func (c *OIDCController) tryLogoutByBearerToken(ctx *gin.Context, claims *tokenDomain.AccessTokenClaims) string {
	if err := c.logoutSvc.LogoutBySessionID(ctx, claims.AccountID, claims.SessionID); err != nil {
		c.logger.Error("Logout by session ID failed", zap.String("session_id", utility.MaskOpaqueID(claims.SessionID)), zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
		ctx.Abort()
		return ""
	}

	// Blacklist the current access token so it cannot be reused
	if claims.ExpiresAt != nil {
		if err := c.tokenSvc.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
			c.logger.Warn("Failed to blacklist access token during logout", zap.String("jti", utility.MaskOpaqueID(claims.ID)), zap.Error(err))
		}
	}

	return claims.ClientID
}

// handlePostLogoutRedirect validates and performs the post-logout redirect.
func (c *OIDCController) handlePostLogoutRedirect(ctx *gin.Context, req logoutRequest, clientID string) {
	client, err := c.clientRepo.FindByClientID(ctx, clientID)
	if err != nil {
		c.logger.Debug("Client lookup failed for post-logout redirect", zap.String("client_id", clientID), zap.Error(err))
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"status": "logged_out"}))
		return
	}

	if !client.ValidatePostLogoutRedirectURI(req.PostLogoutRedirectURI) {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid post_logout_redirect_uri"))
		return
	}

	redirectURI := req.PostLogoutRedirectURI
	if req.State != "" {
		// Validate state parameter length to prevent abuse (e.g., excessively long URLs).
		const maxStateLength = 256
		if len(req.State) > maxStateLength {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "state parameter too long"))
			return
		}
		u, err := url.Parse(redirectURI)
		if err != nil {
			c.logger.Warn("Failed to parse post-logout redirect URI", zap.String("redirect_uri", redirectURI), zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid post_logout_redirect_uri"))
			return
		}
		params := u.Query()
		params.Set("state", req.State)
		u.RawQuery = params.Encode()
		redirectURI = u.String()
	}
	ctx.Redirect(http.StatusFound, redirectURI)
}

// ──────────────────────────────────────────────
// Front-Channel Logout (OIDC Front-Channel Logout 1.0)
// ──────────────────────────────────────────────

// frontChannelLogoutRequest holds the parameters for front-channel logout.
type frontChannelLogoutRequest struct {
	IDTokenHint string `form:"id_token_hint"`
	ClientID    string `form:"client_id"`
}

// FrontChannelLogout handles GET /oidc/frontchannel_logout per OIDC Front-Channel Logout 1.0.
// It renders an HTML page with hidden iframes pointing to each RP's frontchannel_logout_uri,
// allowing the OP to signal logout to multiple RPs simultaneously via the browser.
func (c *OIDCController) FrontChannelLogout(ctx *gin.Context) {
	var req frontChannelLogoutRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	// Identify the account from id_token_hint or Bearer token
	var accountID, sessionID string

	if req.IDTokenHint != "" {
		claims, err := c.logoutSvc.ValidateIDTokenHint(req.IDTokenHint, req.ClientID)
		if err != nil {
			c.logger.Debug("id_token_hint validation failed for front-channel logout", zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid id_token_hint"))
			return
		}
		accountID = claims.Subject
	} else {
		// Try Bearer token
		bearerClaims := c.validateBearerToken(ctx)
		if ctx.IsAborted() {
			return
		}
		if bearerClaims == nil {
			ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "authentication required"))
			return
		}
		accountID = bearerClaims.AccountID
		sessionID = bearerClaims.SessionID
	}

	// Get front-channel logout URIs for this account
	entries, err := c.logoutSvc.GetFrontChannelLogoutURIs(ctx, accountID)
	if err != nil {
		c.logger.Error("Failed to get front-channel logout URIs",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
		return
	}

	// Build iframe HTML
	iframes := buildFrontChannelIframes(entries, c.issuer, sessionID)

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.Status(http.StatusOK)
	_, _ = ctx.Writer.WriteString(`<!DOCTYPE html>
<html>
<head><title>Logout</title></head>
<body>
` + iframes + `
</body>
</html>`)
}

// buildFrontChannelIframes generates hidden iframe elements for front-channel logout.
func buildFrontChannelIframes(entries []oidcService.FrontChannelLogoutEntry, issuer, sessionID string) string {
	if len(entries) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, e := range entries {
		// HTML-escape the URI to prevent stored XSS via malicious frontchannel_logout_uri.
		sb.WriteString(`<iframe src="`)
		sb.WriteString(html.EscapeString(e.URI))
		sb.WriteString(`?iss=`)
		sb.WriteString(url.QueryEscape(issuer))
		if e.SessionRequired && sessionID != "" {
			sb.WriteString(`&sid=`)
			sb.WriteString(url.QueryEscape(sessionID))
		}
		sb.WriteString(`" style="display:none" width="0" height="0"></iframe>`)
		sb.WriteString("\n")
	}
	return sb.String()
}
