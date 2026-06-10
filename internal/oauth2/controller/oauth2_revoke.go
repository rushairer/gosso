package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	"github.com/rushairer/gosso/middleware"
)

// Revoke POST /oauth2/revoke
func (c *OAuth2Controller) Revoke(ctx *gin.Context) {
	var req struct {
		Token string `json:"token" form:"token" binding:"required"`
	}
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Verify the refresh token belongs to the authenticated user before revoking.
	accountIDStr, ok := middleware.GetAccountID(ctx)
	if !ok {
		return
	}
	rt, err := c.tokenSvc.ValidateRefreshToken(ctx, req.Token)
	if err != nil {
		// RFC 7009 §2.1: always return 200 for invalid/unknown tokens
		// to prevent token existence oracle.
		ctx.Status(http.StatusOK)
		return
	}
	if rt.AccountID != accountIDStr {
		// Token belongs to a different user — silently skip revocation.
		ctx.Status(http.StatusOK)
		return
	}

	if err := c.tokenSvc.RevokeRefreshToken(ctx, req.Token); err != nil {
		c.logger.Error("Failed to revoke token", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	ctx.Status(http.StatusOK)
}

// IntrospectRequest is the token introspection request body.
type IntrospectRequest struct {
	Token string `json:"token" binding:"required"`
}

// Introspect POST /oauth2/introspect (RFC 7662)
func (c *OAuth2Controller) Introspect(ctx *gin.Context) {
	var req IntrospectRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Client authentication (Basic Auth or client_id/client_secret) - RFC 7662 requires authentication
	clientID, clientSecret, hasBasicAuth := ctx.Request.BasicAuth()
	if !hasBasicAuth {
		clientID = ctx.PostForm("client_id")
		clientSecret = ctx.PostForm("client_secret")
	}

	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client authentication required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	if err := c.clientAuth.AuthenticateClient(client, clientSecret); err != nil {
		controllerutil.HandleClientAuthError(ctx, err,
			oauth2Service.ErrClientSecretRequired, "client secret is required", "invalid client credentials")
		return
	} else if !client.IsConfidential {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "public clients are not allowed to introspect"})
		return
	}

	result, err := c.tokenSvc.IntrospectToken(ctx, req.Token)
	if err != nil {
		c.logger.Error("Token introspection failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// RFC 7662: only return full token info if the token belongs to the authenticated client
	if tokenClientID, ok := result["client_id"].(string); !ok || tokenClientID != clientID {
		ctx.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	ctx.JSON(http.StatusOK, result)
}
