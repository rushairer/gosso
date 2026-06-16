package controller

import (
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
)

// Revoke POST /oauth2/revoke (RFC 7009)
func (c *OAuth2Controller) Revoke(ctx *gin.Context) {
	var req struct {
		Token        string `json:"token" form:"token" binding:"required,max=2048"`
		TokenHint    string `json:"token_type_hint" form:"token_type_hint" binding:"max=64"`
		ClientID     string `json:"client_id" form:"client_id" binding:"max=128"`
		ClientSecret string `json:"client_secret" form:"client_secret" binding:"max=256"`
	}
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// RFC 7009 requires client authentication where applicable. Basic auth
	// takes precedence over request body credentials per RFC 6749 §2.3.1.
	if clientID, clientSecret, ok := ctx.Request.BasicAuth(); ok {
		req.ClientID = clientID
		req.ClientSecret = clientSecret
	}

	// Resolve client and authenticate if credentials are provided.
	// RFC 7009 §2.1: public clients may revoke tokens without authentication.
	var clientIDMatch string
	if req.ClientID != "" {
		client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
		if err != nil {
			c.clientAuth.DummyAuthenticate()
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
		if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
			controllerutil.HandleClientAuthError(ctx, c.logger, err,
				oauth2Service.ErrClientSecretRequired, "client secret is required", "invalid client credentials")
			return
		}
		clientIDMatch = req.ClientID
	}

	// Try refresh token first (unless hint says otherwise)
	if req.TokenHint != "access_token" {
		rt, err := c.tokenSvc.ValidateRefreshToken(ctx, req.Token)
		if err == nil {
			if clientIDMatch != "" && rt.ClientID != clientIDMatch {
				ctx.Status(http.StatusOK)
				return
			}
			if err := c.tokenSvc.RevokeRefreshToken(ctx, req.Token); err != nil {
				c.logger.Error("Failed to revoke refresh token", zap.Error(err))
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
				return
			}
			ctx.Status(http.StatusOK)
			return
		}
	}

	// Try access token (RFC 7009 §2.1: revoke whatever type matches)
	if req.TokenHint != "refresh_token" {
		claims, err := c.tokenSvc.ValidateAccessTokenWithContext(ctx, req.Token)
		if err == nil && (clientIDMatch == "" || claims.ClientID == clientIDMatch) {
			if revokeErr := c.tokenSvc.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time); revokeErr != nil {
				c.logger.Error("Failed to revoke access token", zap.Error(revokeErr))
			}
		}
	}

	// RFC 7009 §2.1: always return 200 for invalid/unknown tokens
	ctx.Status(http.StatusOK)
}

// IntrospectRequest is the token introspection request body.
type IntrospectRequest struct {
	Token string `json:"token" form:"token" binding:"required,max=2048"`
}

// Introspect POST /oauth2/introspect (RFC 7662)
func (c *OAuth2Controller) Introspect(ctx *gin.Context) {
	var req IntrospectRequest

	// RFC 7662: accept both JSON and application/x-www-form-urlencoded
	if contentType := ctx.GetHeader("Content-Type"); contentType != "" {
		mediaType, _, _ := mime.ParseMediaType(contentType)
		if mediaType == "application/json" {
			if err := ctx.ShouldBindJSON(&req); err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
				return
			}
		} else {
			if err := ctx.ShouldBind(&req); err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
				return
			}
		}
	} else {
		// Default to form binding when Content-Type is not specified
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
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
		// DummyAuthenticate to normalize timing and prevent client ID enumeration.
		c.clientAuth.DummyAuthenticate()
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	if err := c.clientAuth.AuthenticateClient(client, clientSecret); err != nil {
		controllerutil.HandleClientAuthError(ctx, c.logger, err,
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
