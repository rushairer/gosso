package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"

	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

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

// withOptionalLimit prepends a rate limit middleware to handler list if non-nil.
func withOptionalLimit(limit gin.HandlerFunc, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	if limit != nil {
		return append([]gin.HandlerFunc{limit}, handlers...)
	}
	return handlers
}
