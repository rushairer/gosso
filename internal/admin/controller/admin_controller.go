package controller

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountRepository "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	"github.com/rushairer/gosso/middleware"
)

// adminAccountErrorMap maps account lookup/mutation errors to HTTP responses.
var adminAccountErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountRepository.ErrAccountNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "account not found"}},
	{Sentinel: accountRepository.ErrInvalidStatusTransition, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "invalid account status transition"}},
}

// adminDeleteAccountErrorMap maps account deletion errors to HTTP responses.
var adminDeleteAccountErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrAccountNotActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "account is not active"}},
}

// adminRoleErrorMap maps role assignment/removal errors to HTTP responses.
var adminRoleErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrAccountNotActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "account is not active"}},
	{Sentinel: accountRepository.ErrRoleNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "role not found"}},
}

// AdminController handles admin operations
type AdminController struct {
	accountSvc accountService.AccountService
	logger     *zap.Logger
}

// NewAdminController creates a new admin controller instance
func NewAdminController(accountSvc accountService.AccountService, logger *zap.Logger) *AdminController {
	return &AdminController{
		accountSvc: accountSvc,
		logger:     logger,
	}
}

// RegisterRoutes registers admin routes
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
	page, err := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(ctx.DefaultQuery("page_size", "20"))
	if err != nil || pageSize < 1 {
		pageSize = 20
	} else if pageSize > accountRepository.MaxPageSize {
		pageSize = accountRepository.MaxPageSize
	}
	status := ctx.Query("status")
	if status != "" {
		switch status {
		case "active", "suspended", "deleted":
			// valid
		default:
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid status value, must be active, suspended, or deleted"))
			return
		}
	}

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

// isSelfAccount checks if the current admin is operating on their own account.
// Uses UUID parsing to handle format differences (e.g., with/without braces).
// Returns true (fail-safe deny) if the admin ID cannot be determined, to prevent
// self-account operations when the middleware is misconfigured.
func isSelfAccount(ctx *gin.Context, accountID string) bool {
	currentAdminID := ctx.GetString(middleware.ContextKeyAccountID)
	if currentAdminID == "" {
		return true // fail-safe: deny if admin ID is missing (middleware misconfiguration)
	}
	a, err1 := uuid.Parse(currentAdminID)
	b, err2 := uuid.Parse(accountID)
	if err1 != nil || err2 != nil {
		return false
	}
	return a == b
}

// GetAccount GET /api/admin/accounts/:account_id
func (c *AdminController) GetAccount(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	account, err := c.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminAccountErrorMap,
			http.StatusInternalServerError, "Failed to get account")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(account))
}

// DeleteAccount DELETE /api/admin/accounts/:account_id
func (c *AdminController) DeleteAccount(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	if err := c.accountSvc.SoftDeleteAccount(ctx, accountID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminDeleteAccountErrorMap,
			http.StatusInternalServerError, "Failed to delete account")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("account deleted"))
}

// DisableAccount POST /api/admin/accounts/:account_id/disable
func (c *AdminController) DisableAccount(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	if err := c.accountSvc.SuspendAccount(ctx, accountID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminAccountErrorMap,
			http.StatusInternalServerError, "Failed to disable account")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("account disabled"))
}

// EnableAccount POST /api/admin/accounts/:account_id/enable
func (c *AdminController) EnableAccount(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	if err := c.accountSvc.ActivateAccount(ctx, accountID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminAccountErrorMap,
			http.StatusInternalServerError, "Failed to enable account")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("account enabled"))
}

// GetAccountRoles GET /api/admin/accounts/:account_id/roles
func (c *AdminController) GetAccountRoles(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	roles, err := c.accountSvc.GetAccountRoles(ctx, accountID)
	if err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminAccountErrorMap,
			http.StatusInternalServerError, "Failed to get account roles")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(roles))
}

// AddRoleRequestBody is the request body for adding a role
type AddRoleRequestBody struct {
	RoleID string `json:"role_id" binding:"required"`
}

// AddRole POST /api/admin/accounts/:account_id/roles
func (c *AdminController) AddRole(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	var req AddRoleRequestBody
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}
	if _, ok := controllerutil.ValidateUUID(ctx, req.RoleID, "role_id"); !ok {
		return
	}

	if err := c.accountSvc.AssignRole(ctx, accountID, req.RoleID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminRoleErrorMap,
			http.StatusInternalServerError, "Failed to assign role")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("role assigned"))
}

// RemoveRole DELETE /api/admin/accounts/:account_id/roles/:role_id
func (c *AdminController) RemoveRole(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	roleID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("role_id"), "role_id")
	if !ok {
		return
	}

	if err := c.accountSvc.RemoveRole(ctx, accountID, roleID); err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, adminRoleErrorMap,
			http.StatusInternalServerError, "Failed to remove role")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("role removed"))
}
