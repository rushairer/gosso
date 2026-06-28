package controller

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
	"github.com/rushairer/gosso/middleware"
)

// clientErrorMap maps client operation errors to HTTP responses.
var clientErrorMap = []controllerutil.ErrorRule{
	{Sentinel: oauth2Domain.ErrClientNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "client not found"}},
	{Sentinel: oauth2Service.ErrClientAccessDenied, Mapping: controllerutil.ErrorMapping{Status: http.StatusForbidden, Message: "access denied"}},
}

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

	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
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
		AllowReservedScopes:    canManageReservedClientScopes(ctx),
	})
	if err != nil {
		if isValidationError(err) {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		c.logger.Error("Failed to register client", zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(accountID)))
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
	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
	}

	clients, err := c.clientSvc.FindByAccountID(ctx, accountID)
	if err != nil {
		c.logger.Error("Failed to list clients", zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(accountID)))
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
	clientID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("client_id"), "client_id")
	if !ok {
		return
	}

	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		c.logger.Debug("Client lookup failed in GetClient", zap.Error(err), zap.String("client_id", clientID))
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "access denied"))
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
	clientID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("client_id"), "client_id")
	if !ok {
		return
	}

	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
	}

	var req UpdateClientRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	svcReq := &oauth2Service.UpdateClientRequest{
		Name:                   req.Name,
		Description:            req.Description,
		RedirectURIs:           req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs,
		GrantTypes:             req.GrantTypes,
		Scopes:                 req.Scopes,
		AllowReservedScopes:    canManageReservedClientScopes(ctx),
	}

	client, err := c.clientSvc.UpdateClientByAccountID(ctx, accountID, clientID, svcReq)
	if err != nil {
		if isValidationError(err) {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		controllerutil.AbortWithServiceError(ctx, c.logger, err, clientErrorMap,
			http.StatusBadRequest, "failed to update client")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(client))
}

// UpdateClientRequest is the request body for updating a client
type UpdateClientRequest struct {
	Name                   *string  `json:"name"`
	Description            *string  `json:"description"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	GrantTypes             []string `json:"grant_types"`
	Scopes                 []string `json:"scopes"`
}

// DeleteClient DELETE /api/oauth2/clients/:client_id
func (c *ClientController) DeleteClient(ctx *gin.Context) {
	clientID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("client_id"), "client_id")
	if !ok {
		return
	}

	accountID, ok := middleware.RequireAccountID(ctx)
	if !ok {
		return
	}

	if err := c.clientSvc.DeleteClient(ctx, accountID, clientID); err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, clientErrorMap,
			http.StatusInternalServerError, "Failed to delete client")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("client deleted"))
}

// isValidationError checks if the error is a client validation error (as opposed to an internal server error).
func isValidationError(err error) bool {
	return oauth2Service.IsValidationError(err)
}

func canManageReservedClientScopes(ctx *gin.Context) bool {
	claimsRaw, exists := ctx.Get(middleware.ContextKeyClaims)
	if !exists {
		return false
	}
	claims, ok := claimsRaw.(*tokenDomain.AccessTokenClaims)
	if !ok {
		return false
	}
	hasAdminRole := false
	for _, role := range claims.Roles {
		if role == authService.RoleAdmin {
			hasAdminRole = true
			break
		}
	}
	if !hasAdminRole {
		return false
	}
	for _, scope := range strings.Fields(claims.Scope) {
		if scope == authService.ScopeAdmin {
			return true
		}
	}
	return false
}
