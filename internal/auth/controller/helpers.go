package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"

	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

const authCookieName = "access_token"

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

func setSSOAuthCookie(ctx *gin.Context, accessToken string, maxAgeSeconds int, secure bool) {
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     authCookieName,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSSOAuthCookie(ctx *gin.Context, secure bool) {
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func isSecureRequest(ctx *gin.Context) bool {
	return ctx.Request.TLS != nil || ctx.GetHeader("X-Forwarded-Proto") == "https"
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

// withOptionalLimit prepends a rate limit middleware to handler list if non-nil.
func withOptionalLimit(limit gin.HandlerFunc, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	if limit != nil {
		return append([]gin.HandlerFunc{limit}, handlers...)
	}
	return handlers
}
