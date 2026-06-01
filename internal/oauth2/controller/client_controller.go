package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

// ClientController OAuth2 客户端管理控制器
type ClientController struct {
	clientSvc oauth2Service.OAuth2ClientService
	logger    *zap.Logger
}

// NewClientController 创建客户端管理控制器实例
func NewClientController(clientSvc oauth2Service.OAuth2ClientService, logger *zap.Logger) *ClientController {
	return &ClientController{clientSvc: clientSvc, logger: logger}
}

// RegisterRoutes 注册客户端管理路由
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

// RegisterClientRequest 注册客户端请求体
type RegisterClientRequest struct {
	Name           string   `json:"name" binding:"required"`
	Description    string   `json:"description"`
	RedirectURIs   []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes     []string `json:"grant_types"`
	Scopes         []string `json:"scopes"`
	IsConfidential bool     `json:"is_confidential"`
}

// RegisterClientResponse 注册客户端响应体
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

	accountID, _ := ctx.Get(middleware.ContextKeyAccountID)

	client, secret, err := c.clientSvc.RegisterClient(ctx, &oauth2Service.RegisterClientRequest{
		AccountID:      accountID.(string),
		Name:           req.Name,
		Description:    req.Description,
		RedirectURIs:   req.RedirectURIs,
		GrantTypes:     req.GrantTypes,
		Scopes:         req.Scopes,
		IsConfidential: req.IsConfidential,
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
	accountID, _ := ctx.Get(middleware.ContextKeyAccountID)

	clients, err := c.clientSvc.FindByAccountID(ctx, accountID.(string))
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

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "client not found"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(client))
}

// UpdateClientRequest 更新客户端请求体
type UpdateClientRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
}

// UpdateClient PUT /api/oauth2/clients/:client_id
func (c *ClientController) UpdateClient(ctx *gin.Context) {
	clientID := ctx.Param("client_id")

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "client not found"))
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
		client.RedirectURIs = req.RedirectURIs
	}
	if req.GrantTypes != nil {
		client.GrantTypes = req.GrantTypes
	}
	if req.Scopes != nil {
		client.Scopes = req.Scopes
	}
	client.UpdatedAt = time.Now()

	if err := c.clientSvc.UpdateClient(ctx, client); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to update client"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(client))
}

// DeleteClient DELETE /api/oauth2/clients/:client_id
func (c *ClientController) DeleteClient(ctx *gin.Context) {
	clientID := ctx.Param("client_id")

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "client not found"))
		return
	}

	if err := c.clientSvc.DeleteClient(ctx, client.ID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to delete client"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("client deleted"))
}
