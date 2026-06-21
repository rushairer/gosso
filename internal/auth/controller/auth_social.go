package controller

import (
	"crypto/subtle"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	"github.com/rushairer/gosso/internal/utility"
)

// validSocialProviders is the allowlist of supported social login providers.
var validSocialProviders = map[string]bool{
	"google": true,
	"github": true,
	"wechat": true,
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

	// Generate cryptographic nonce for CSRF protection, and bind the client IP
	// into the state parameter to prevent attacks where an attacker obtains the
	// oauth_state cookie from a different network location (e.g., via subdomain XSS).
	// Format: "nonce:clientIP" — only the nonce is stored in the cookie for CSRF validation.
	nonce, err := authService.GenerateAuthState()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to generate state"))
		return
	}
	clientIP := ctx.ClientIP()
	state := nonce + ":" + clientIP
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    nonce,
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

	// Validate state parameter (CSRF protection + IP binding).
	// The state format is "nonce:clientIP"; only the nonce is stored in the cookie.
	state := ctx.Query("state")
	savedNonce, _ := ctx.Cookie("oauth_state")
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/api/auth/social",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	if state == "" || savedNonce == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid or missing state parameter"))
		return
	}
	// Parse state to extract nonce and IP
	stateNonce, stateIP, ok := splitOAuthState(state)
	if !ok || subtle.ConstantTimeCompare([]byte(stateNonce), []byte(savedNonce)) != 1 {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid or missing state parameter"))
		return
	}
	// Validate IP binding: the callback IP must match the IP that initiated the flow.
	// Uses /24 subnet matching to tolerate minor network changes (e.g., CDN proxies).
	if stateIP != "" {
		callbackIP := ctx.ClientIP()
		if !sameSubnet24(stateIP, callbackIP) {
			c.logger.Warn("Social login state IP mismatch",
				zap.String("state_ip", utility.MaskOpaqueID(stateIP)),
				zap.String("callback_ip", utility.MaskOpaqueID(callbackIP)))
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid or missing state parameter"))
			return
		}
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
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(mfaRequiredResponse(result.MFAToken, result.MFATypes)))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(tokenResponse(
		result.AccessToken, result.RefreshToken, result.Session.ID, int(c.tokenMgr.AccessExpiry().Seconds()),
	)))
}

// splitOAuthState splits an OAuth state string of the form "nonce:ip" into its components.
// Returns ("", "", false) if the format is invalid.
func splitOAuthState(state string) (nonce, ip string, ok bool) {
	// Find the last colon to handle IPv6 addresses that contain colons.
	// The nonce is always hex (no colons), so the first colon is the separator.
	idx := -1
	for i, ch := range state {
		if ch == ':' {
			idx = i
			break
		}
	}
	if idx <= 0 || idx >= len(state)-1 {
		return "", "", false
	}
	return state[:idx], state[idx+1:], true
}

// sameSubnet24 checks whether two IP addresses belong to the same /24 subnet.
// This provides a balance between strict IP matching (too restrictive for mobile users)
// and no IP matching (too permissive). Returns false if either IP cannot be parsed
// (fail-closed to prevent bypassing the check with crafted IPs).
func sameSubnet24(ip1, ip2 string) bool {
	parsed1 := net.ParseIP(ip1)
	parsed2 := net.ParseIP(ip2)
	if parsed1 == nil || parsed2 == nil {
		return false
	}
	// Normalize to IPv4 if possible for consistent /24 comparison
	v4_1 := parsed1.To4()
	v4_2 := parsed2.To4()
	if v4_1 != nil && v4_2 != nil {
		// Compare first 3 octets (/24)
		return v4_1[0] == v4_2[0] && v4_1[1] == v4_2[1] && v4_1[2] == v4_2[2]
	}
	// For IPv6, use /48 prefix comparison (equivalent rough granularity).
	// Note: IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1) that weren't
	// normalized to IPv4 by To4() above will be compared as pure IPv6,
	// resulting in a false mismatch (fail-closed, safe).
	v1 := parsed1.To16()
	v2 := parsed2.To16()
	if v1 == nil || v2 == nil {
		return false
	}
	// Compare first 6 bytes (/48)
	for i := 0; i < 6; i++ {
		if v1[i] != v2[i] {
			return false
		}
	}
	return true
}
