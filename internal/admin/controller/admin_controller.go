package controller

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

// AdminController 管理员控制器
type AdminController struct {
	accountSvc accountService.AccountService
	logger     *zap.Logger
}

// NewAdminController 创建管理员控制器实例
func NewAdminController(accountSvc accountService.AccountService, logger *zap.Logger) *AdminController {
	return &AdminController{
		accountSvc: accountSvc,
		logger:     logger,
	}
}

// RegisterRoutes 注册管理员路由
func (c *AdminController) RegisterRoutes(rg *gin.RouterGroup) {
	accounts := rg.Group("/accounts")
	{
		accounts.GET("", c.ListAccounts)
		accounts.GET("/:account_id", c.GetAccount)
		accounts.DELETE("/:account_id", c.DeleteAccount)
		accounts.POST("/:account_id/disable", c.DisableAccount)
		accounts.POST("/:account_id/enable", c.EnableAccount)
		accounts.GET("/:account_id/roles", c.GetAccountRoles)
		accounts.POST("/:account_id/roles", c.AddRole)
		accounts.DELETE("/:account_id/roles/:role_id", c.RemoveRole)
	}
}

// ListAccounts GET /api/admin/accounts
func (c *AdminController) ListAccounts(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "20"))
	status := ctx.Query("status")

	accounts, total, err := c.accountSvc.ListAccounts(ctx, page, pageSize, status)
	if err != nil {
		c.logger.Error("Failed to list accounts", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to list accounts"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"items":     accounts,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	}))
}

// GetAccount GET /api/admin/accounts/:account_id
func (c *AdminController) GetAccount(ctx *gin.Context) {
	accountID := ctx.Param("account_id")

	account, err := c.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gouno.NewErrorResponse(http.StatusNotFound, "account not found"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(account))
}

// DeleteAccount DELETE /api/admin/accounts/:account_id
func (c *AdminController) DeleteAccount(ctx *gin.Context) {
	accountID := ctx.Param("account_id")

	if err := c.accountSvc.SoftDeleteAccount(ctx, accountID); err != nil {
		c.logger.Error("Failed to delete account", zap.Error(err), zap.String("account_id", accountID))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("account deleted"))
}

// DisableAccount POST /api/admin/accounts/:account_id/disable
func (c *AdminController) DisableAccount(ctx *gin.Context) {
	accountID := ctx.Param("account_id")

	if err := c.accountSvc.SuspendAccount(ctx, accountID); err != nil {
		c.logger.Error("Failed to disable account", zap.Error(err), zap.String("account_id", accountID))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("account disabled"))
}

// EnableAccount POST /api/admin/accounts/:account_id/enable
func (c *AdminController) EnableAccount(ctx *gin.Context) {
	accountID := ctx.Param("account_id")

	if err := c.accountSvc.ActivateAccount(ctx, accountID); err != nil {
		c.logger.Error("Failed to enable account", zap.Error(err), zap.String("account_id", accountID))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("account enabled"))
}

// GetAccountRoles GET /api/admin/accounts/:account_id/roles
func (c *AdminController) GetAccountRoles(ctx *gin.Context) {
	accountID := ctx.Param("account_id")

	roles, err := c.accountSvc.GetAccountRoles(ctx, accountID)
	if err != nil {
		c.logger.Error("Failed to get account roles", zap.Error(err), zap.String("account_id", accountID))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to get roles"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(roles))
}

// AddRoleRequestBody 添加角色请求体
type AddRoleRequestBody struct {
	RoleID string `json:"role_id" binding:"required"`
}

// AddRole POST /api/admin/accounts/:account_id/roles
func (c *AdminController) AddRole(ctx *gin.Context) {
	accountID := ctx.Param("account_id")

	var req AddRoleRequestBody
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if err := c.accountSvc.AssignRole(ctx, accountID, req.RoleID); err != nil {
		c.logger.Error("Failed to assign role", zap.Error(err), zap.String("account_id", accountID))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("role assigned"))
}

// RemoveRole DELETE /api/admin/accounts/:account_id/roles/:role_id
func (c *AdminController) RemoveRole(ctx *gin.Context) {
	accountID := ctx.Param("account_id")
	roleID := ctx.Param("role_id")

	if err := c.accountSvc.RemoveRole(ctx, accountID, roleID); err != nil {
		c.logger.Error("Failed to remove role", zap.Error(err), zap.String("account_id", accountID))
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("role removed"))
}
