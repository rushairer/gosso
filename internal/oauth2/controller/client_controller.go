package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
)

// ClientController handles OAuth2 client management endpoints
type ClientController struct {
	clientSvc oauth2Service.OAuth2ClientService
	logger    *zap.Logger
}

// NewClientController creates a new client management controller instance
func NewClientController(clientSvc oauth2Service.OAuth2ClientService, logger *zap.Logger) *ClientController {
	return &ClientController{clientSvc: clientSvc, logger: logger}
}

// RegisterRoutes registers client management routes
func (c *ClientController) RegisterRoutes(rg *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	clients := rg.Group("/oauth2/clients")
	clients.Use(authMiddleware)
	{
		clients.GET("", c.ListClients)
		clients.POST("", c.RegisterClient)
		clients.GET("/:client_id", c.GetClient)
		clients.PUT("/:client_id", c.UpdateClient)
		clients.DELETE("/:client_id", c.DeleteClient)
	}
}

// RegisterClientRequest is the request body for registering a client
type RegisterClientRequest struct {
	Name                   string   `json:"name" binding:"required,max=255"`
	Description            string   `json:"description" binding:"max=2000"`
	RedirectURIs           []string `json:"redirect_uris" binding:"required,min=1"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	GrantTypes             []string `json:"grant_types"`
	Scopes                 []string `json:"scopes"`
	IsConfidential         bool     `json:"is_confidential"`
}

// RegisterClientResponse is the response body for registering a client
type RegisterClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Name         string `json:"name"`
}

// RegisterClient POST /api/oauth2/clients
func (c *ClientController) RegisterClient(ctx *gin.Context) {
	var req RegisterClientRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	accountIDRaw, exists := ctx.Get(middleware.ContextKeyAccountID)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}
	accountID, ok := accountIDRaw.(string)
	if !ok || accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}

	// Validate redirect URI schemes (no fragments per RFC 6749 §3.1.2)
	for _, uri := range req.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "redirect_uris must use http or https scheme without fragment"))
			return
		}
	}
	for _, uri := range req.PostLogoutRedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "post_logout_redirect_uris must use http or https scheme without fragment"))
			return
		}
	}

	if len(req.GrantTypes) > 0 {
		if err := validateGrantTypes(req.GrantTypes); err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
	}

	client, secret, err := c.clientSvc.RegisterClient(ctx, &oauth2Service.RegisterClientRequest{
		AccountID:              accountID,
		Name:                   req.Name,
		Description:            req.Description,
		RedirectURIs:           req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs,
		GrantTypes:             req.GrantTypes,
		Scopes:                 req.Scopes,
		IsConfidential:         req.IsConfidential,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to register client"))
		return
	}

	ctx.JSON(http.StatusCreated, gouno.NewSuccessResponse(RegisterClientResponse{
		ClientID:     client.ClientID,
		ClientSecret: secret,
		Name:         client.Name,
	}))
}

// ListClients GET /api/oauth2/clients
func (c *ClientController) ListClients(ctx *gin.Context) {
	accountIDRaw, exists := ctx.Get(middleware.ContextKeyAccountID)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}
	accountID, ok := accountIDRaw.(string)
	if !ok || accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return
	}

	clients, err := c.clientSvc.FindByAccountID(ctx, accountID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to list clients"))
		return
	}

	if clients == nil {
		clients = []*oauth2Domain.OAuth2Client{}
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(clients))
}

// GetClient GET /api/oauth2/clients/:client_id
func (c *ClientController) GetClient(ctx *gin.Context) {
	clientID := ctx.Param("client_id")

	accountID, ok := getAccountID(ctx)
	if !ok {
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "client not found"))
		return
	}

	if client.AccountID != accountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "access denied"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(client))
}

// UpdateClient PUT /api/oauth2/clients/:client_id
func (c *ClientController) UpdateClient(ctx *gin.Context) {
	clientID := ctx.Param("client_id")

	accountID, ok := getAccountID(ctx)
	if !ok {
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "client not found"))
		return
	}

	if client.AccountID != accountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "access denied"))
		return
	}

	var req UpdateClientRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if req.Name != "" {
		client.Name = req.Name
	}
	if req.Description != "" {
		client.Description = req.Description
	}
	if req.RedirectURIs != nil {
		for _, uri := range req.RedirectURIs {
			u, err := url.Parse(uri)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
				ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "redirect_uris must use http or https scheme without fragment"))
				return
			}
		}
		client.RedirectURIs = req.RedirectURIs
	}
	if req.GrantTypes != nil {
		if err := validateGrantTypes(req.GrantTypes); err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		client.GrantTypes = req.GrantTypes
	}
	if req.Scopes != nil {
		client.Scopes = req.Scopes
	}
	if req.PostLogoutRedirectURIs != nil {
		for _, uri := range req.PostLogoutRedirectURIs {
			u, err := url.Parse(uri)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
				ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "post_logout_redirect_uris must use http or https scheme without fragment"))
				return
			}
		}
		client.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	}
	client.UpdatedAt = time.Now()

	if err := c.clientSvc.UpdateClient(ctx, client); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to update client"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(client))
}

// UpdateClientRequest is the request body for updating a client
type UpdateClientRequest struct {
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	GrantTypes             []string `json:"grant_types"`
	Scopes                 []string `json:"scopes"`
}

// DeleteClient DELETE /api/oauth2/clients/:client_id
func (c *ClientController) DeleteClient(ctx *gin.Context) {
	clientID := ctx.Param("client_id")

	accountID, ok := getAccountID(ctx)
	if !ok {
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "client not found"))
		return
	}

	if client.AccountID != accountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "access denied"))
		return
	}

	if err := c.clientSvc.DeleteClient(ctx, client.ID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to delete client"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("client deleted"))
}

// getAccountID extracts the account ID from the gin context with safe type assertion.
func getAccountID(ctx *gin.Context) (string, bool) {
	raw, exists := ctx.Get(middleware.ContextKeyAccountID)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return "", false
	}
	accountID, ok := raw.(string)
	if !ok || accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return "", false
	}
	return accountID, true
}

var validGrantTypes = []string{
	oauth2Domain.GrantTypeAuthorizationCode,
	oauth2Domain.GrantTypeRefreshToken,
	oauth2Domain.GrantTypeClientCredentials,
	oauth2Domain.GrantTypeDeviceCode,
}

func validateGrantTypes(types []string) error {
	for _, gt := range types {
		found := false
		for _, valid := range validGrantTypes {
			if gt == valid {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid grant_type: %q", gt)
		}
	}
	return nil
}
