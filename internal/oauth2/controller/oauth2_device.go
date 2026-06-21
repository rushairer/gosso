package controller

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
	"github.com/rushairer/gosso/middleware"
)

// renderTemplate executes the given HTML template with data and writes the result to ctx.
// Returns true if the template was rendered successfully, false if an error occurred (in which case
// an HTTP 500 response is sent and the caller should return).
func (c *OAuth2Controller) renderTemplate(ctx *gin.Context, tmpl *template.Template, data gin.H) bool {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		c.logger.Error("Failed to render template", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return false
	}
	ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
	return true
}

// DeviceCodeRequestParams is the device code initiation request body.
type DeviceCodeRequestParams struct {
	ClientID     string `form:"client_id" binding:"required,max=128"`
	ClientSecret string `form:"client_secret" binding:"max=256"`
	Scope        string `form:"scope" binding:"max=2048"`
}

// DeviceCodeRequest POST /oauth2/device/code
func (c *OAuth2Controller) DeviceCodeRequest(ctx *gin.Context) {
	var req DeviceCodeRequestParams
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id is required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		c.clientAuth.DummyAuthenticate()
		c.logger.Warn("Client lookup failed for device code request", zap.Error(err), zap.String("client_id", req.ClientID))
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if !client.HasGrantType(oauth2Domain.GrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "device_code grant not allowed"})
		return
	}

	// Client authentication for confidential clients (RFC 8628 §3.1)
	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		controllerutil.HandleClientAuthError(ctx, c.logger, err,
			oauth2Service.ErrClientSecretRequired,
			"client_secret required for confidential client", "invalid client_secret")
		return
	}

	scopes := splitScope(req.Scope)
	originalScope := req.Scope
	if len(scopes) == 0 {
		scopes = client.Scopes
	} else {
		scopes = client.ValidateScope(scopes)
		if len(scopes) == 0 && originalScope != "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "none of the requested scopes are valid for this client"})
			return
		}
	}

	dc, err := c.deviceCodeSvc.CreateDeviceCode(ctx, req.ClientID, scopes)
	if err != nil {
		c.logger.Error("Failed to create device code", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	verificationURI, _ := url.JoinPath(c.issuer, "/oauth2/device")
	ctx.JSON(http.StatusOK, gin.H{
		"device_code":               dc.DeviceCode,
		"user_code":                 dc.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?" + url.Values{"user_code": {dc.UserCode}}.Encode(),
		"expires_in":                int(time.Until(dc.ExpiresAt).Seconds()),
		"interval":                  dc.Interval,
	})
}

// DeviceUserPage GET /oauth2/device
func (c *OAuth2Controller) DeviceUserPage(ctx *gin.Context) {
	userCode := ctx.Query("user_code")

	if userCode == "" {
		c.renderTemplate(ctx, c.deviceTmpl, gin.H{
			"UserCode": "",
			"CSPNonce": middleware.GetCSPNonce(ctx),
		})
		return
	}

	dc, err := c.deviceCodeSvc.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		c.renderTemplate(ctx, c.deviceTmpl, gin.H{
			"UserCode": "",
			"Error":    "Invalid or expired code. Please try again.",
			"CSPNonce": middleware.GetCSPNonce(ctx),
		})
		return
	}

	if dc.IsExpired() || dc.Status != oauth2Domain.DeviceCodeStatusPending {
		c.renderTemplate(ctx, c.deviceTmpl, gin.H{
			"UserCode": "",
			"Error":    "This code has expired or is no longer valid.",
			"CSPNonce": middleware.GetCSPNonce(ctx),
		})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, dc.ClientID)
	if err != nil {
		c.logger.Debug("Client lookup failed for device user page", zap.Error(err), zap.String("client_id", dc.ClientID))
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	c.renderTemplate(ctx, c.deviceTmpl, gin.H{
		"UserCode":   dc.UserCode,
		"ClientName": client.Name,
		"Scopes":     dc.Scopes,
		"CSRFToken":  csrfTokenFromCookie(ctx),
		"CSPNonce":   middleware.GetCSPNonce(ctx),
	})
}

// DeviceUserSubmitRequest is the device authorization form submission.
type DeviceUserSubmitRequest struct {
	DeviceCode string `form:"device_code" binding:"max=128"`
	UserCode   string `form:"user_code" binding:"max=32"`
	Approved   string `form:"approved" binding:"required"`
}

// DeviceUserSubmit POST /oauth2/device
func (c *OAuth2Controller) DeviceUserSubmit(ctx *gin.Context) {
	var req DeviceUserSubmitRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Validate CSRF token (double-submit cookie pattern)
	cookieToken := csrfTokenFromCookie(ctx)
	formToken := ctx.PostForm("csrf_token")
	if cookieToken == "" || formToken == "" || subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) != 1 {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "invalid_csrf", "error_description": "CSRF token mismatch"})
		return
	}

	// Look up device code by user_code if provided.
	// Use the hash-based methods since the raw device code is not stored in Redis.
	// When both device_code and user_code are provided, prefer user_code lookup
	// to ensure the device_code corresponds to the same authorization session.
	dcHash := ""
	if req.UserCode != "" {
		dc, err := c.deviceCodeSvc.GetDeviceCodeByUserCode(ctx, req.UserCode)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired user code"})
			return
		}
		dcHash = dc.Hash
	}

	accountIDStr, ok := c.authenticateRequest(ctx)
	if !ok {
		return
	}

	if dcHash != "" {
		// Use hash-based methods (from user code lookup — raw device code not available)
		if req.Approved == "true" {
			if err := c.deviceCodeSvc.AuthorizeDeviceCodeByHash(ctx, dcHash, accountIDStr); err != nil {
				c.logger.Warn("Device code authorization failed", zap.Error(err), zap.String("device_code_hash", utility.MaskOpaqueID(dcHash)))
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device code authorization failed"})
				return
			}
		} else {
			if err := c.deviceCodeSvc.DenyDeviceCodeByHash(ctx, dcHash); err != nil {
				c.logger.Warn("Device code denial failed", zap.Error(err), zap.String("device_code_hash", utility.MaskOpaqueID(dcHash)))
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device code denial failed"})
				return
			}
		}
	} else {
		// Fallback: raw device code was provided in the form submission
		if req.Approved == "true" {
			if err := c.deviceCodeSvc.AuthorizeDeviceCode(ctx, req.DeviceCode, accountIDStr); err != nil {
				c.logger.Warn("Device code authorization failed", zap.Error(err), zap.String("device_code", utility.MaskOpaqueID(req.DeviceCode)))
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device code authorization failed"})
				return
			}
		} else {
			if err := c.deviceCodeSvc.DenyDeviceCode(ctx, req.DeviceCode); err != nil {
				c.logger.Warn("Device code denial failed", zap.Error(err), zap.String("device_code", utility.MaskOpaqueID(req.DeviceCode)))
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device code denial failed"})
				return
			}
		}
	}

	isApproved := req.Approved == "true"
	title := "Authorization Denied"
	message := "The device has been denied access. You may close this page."
	if isApproved {
		title = "Authorization Granted"
		message = "The device has been authorized. You may close this page."
	}
	c.renderTemplate(ctx, c.resultTmpl, gin.H{
		"CSPNonce": middleware.GetCSPNonce(ctx),
		"Title":    title,
		"Message":  message,
	})
}

func (c *OAuth2Controller) handleDeviceCodeGrant(ctx *gin.Context, req *TokenRequest) {
	if req.ClientID == "" || req.DeviceCode == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id and device_code required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		c.clientAuth.DummyAuthenticate()
		c.logger.Warn("Client lookup failed for device code grant", zap.Error(err), zap.String("client_id", req.ClientID))
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !client.HasGrantType(oauth2Domain.GrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "device_code grant not allowed"})
		return
	}

	// Client authentication for confidential clients
	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		controllerutil.HandleClientAuthError(ctx, c.logger, err,
			oauth2Service.ErrClientSecretRequired,
			"client_secret required", "invalid client_secret")
		return
	}

	dc, err := c.deviceCodeSvc.GetDeviceCode(ctx, req.DeviceCode)
	if err != nil {
		c.logger.Debug("Device code lookup failed", zap.Error(err), zap.String("device_code", utility.MaskOpaqueID(req.DeviceCode)))
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "device code not found"})
		return
	}

	if dc.ClientID != req.ClientID {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "device code was not issued to this client"})
		return
	}

	if dc.IsExpired() {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "expired_token", "error_description": "device code has expired"})
		return
	}

	if err := c.deviceCodeSvc.CheckAndUpdatePollRate(ctx, req.DeviceCode); err != nil {
		ctx.Header("Retry-After", fmt.Sprintf("%d", dc.Interval))
		ctx.JSON(http.StatusTooManyRequests, gin.H{"error": "slow_down", "error_description": "too many requests"})
		return
	}

	switch dc.Status {
	case oauth2Domain.DeviceCodeStatusPending:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "authorization_pending", "error_description": "authorization is pending"})
		return
	case oauth2Domain.DeviceCodeStatusDenied:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "access_denied", "error_description": "device authorization was denied"})
		return
	case oauth2Domain.DeviceCodeStatusAuthorized:
		// Continue to account validation and atomic claim.
	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "device code already consumed"})
		return
	}

	// Verify account is still active BEFORE claiming the device code.
	// If checked after claim, an inactive account would waste the device code.
	if !c.accountValidator.IsAccountActive(ctx, dc.AccountID) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "account is not active"})
		return
	}

	// Atomically claim the device code (status authorized→used) to prevent double-use.
	// The Lua script handles all status validation atomically, so no non-atomic
	// status check is needed before this call.
	claimedDC, err := c.deviceCodeSvc.ClaimAuthorizedDeviceCode(ctx, req.DeviceCode, req.ClientID)
	if err != nil {
		c.logger.Warn("Device code claim failed", zap.Error(err), zap.String("device_code", utility.MaskOpaqueID(req.DeviceCode)), zap.String("client_id", req.ClientID))
		// Distinguish expired vs consumed per RFC 8628 §3.5
		errorDesc := "device code already consumed"
		if lookupDC, lookupErr := c.deviceCodeSvc.GetDeviceCode(ctx, req.DeviceCode); lookupErr == nil && lookupDC.IsExpired() {
			errorDesc = "device code has expired"
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": errorDesc})
		return
	}

	// Use claimedDC for token issuance
	dc = claimedDC

	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: dc.AccountID,
		Scope:     strings.Join(dc.Scopes, " "),
		ClientID:  dc.ClientID,
	})
	if err != nil {
		c.logger.Error("Failed to generate access token for device code", zap.Error(err), zap.String("client_id", dc.ClientID))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	var refreshToken *tokenDomain.RefreshToken
	var refreshTokenStr string
	if client.HasGrantType(oauth2Domain.GrantTypeRefreshToken) {
		refreshToken, err = c.tokenSvc.GenerateRefreshToken(ctx, dc.AccountID, dc.ClientID, "", strings.Join(dc.Scopes, " "))
		if err != nil {
			c.logger.Error("Failed to generate refresh token for device code", zap.Error(err), zap.String("client_id", dc.ClientID))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		refreshTokenStr = refreshToken.Token
	}

	idToken, ok := c.maybeGenerateIDToken(ctx, dc.AccountID, dc.ClientID, dc.Scopes, "", dc.AuthorizedAt, accessToken, nil)
	if !ok {
		return
	}

	response := gin.H{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":         strings.Join(dc.Scopes, " "),
	}
	if idToken != "" {
		response["id_token"] = idToken
	}
	if refreshTokenStr != "" {
		response["refresh_token"] = refreshTokenStr
	}

	controllerutil.SetNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, response)
}
