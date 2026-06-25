package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountRepository "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditRepository "github.com/rushairer/gosso/internal/audit/repository"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/middleware"
)

// adminAccountErrorMap maps account lookup/mutation errors to HTTP responses.
var adminAccountErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountRepository.ErrAccountNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "account not found"}},
	{Sentinel: accountRepository.ErrInvalidStatusTransition, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "invalid account status transition"}},
}

// adminCreateAccountErrorMap maps account creation errors to HTTP responses.
var adminCreateAccountErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrUsernameAlreadyTaken, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "username already taken"}},
	{Sentinel: accountService.ErrEmailAlreadyRegistered, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "email already registered"}},
	{Sentinel: accountService.ErrPhoneAlreadyRegistered, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "phone already registered"}},
}

// adminDeleteAccountErrorMap maps account deletion errors to HTTP responses.
var adminDeleteAccountErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrAccountNotActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "account is not active"}},
}

// adminRoleErrorMap maps role assignment/removal errors to HTTP responses.
var adminRoleErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrAccountNotActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusConflict, Message: "account is not active"}},
	{Sentinel: accountRepository.ErrRoleNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "role not found"}},
	{Sentinel: accountRepository.ErrRoleAssignmentNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "role assignment not found"}},
}

// adminConsentErrorMap maps consent operation errors to HTTP responses.
var adminConsentErrorMap = []controllerutil.ErrorRule{
	{Sentinel: oauth2Domain.ErrConsentNotFound, Mapping: controllerutil.ErrorMapping{Status: http.StatusNotFound, Message: "consent not found"}},
}

// AdminConsentManager defines consent operations needed by the admin controller.
type AdminConsentManager interface {
	ListConsentsByAccountID(ctx context.Context, accountID string) ([]*oauth2Domain.Consent, error)
	DeleteConsent(ctx context.Context, accountID, clientID string) error
}

// AdminAuditQueryManager defines audit log query operations needed by the admin controller.
type AdminAuditQueryManager interface {
	Query(ctx context.Context, filter auditRepository.AuditQueryFilter) ([]*auditDomain.AuditRecord, int, error)
}

// AdminLockoutManager defines account lockout operations needed by the admin controller.
type AdminLockoutManager interface {
	GetLockoutStatus(ctx context.Context, accountID string) (*authService.LockoutStatus, error)
	ClearLockout(ctx context.Context, accountID string) error
}

// AdminController handles admin operations
type AdminController struct {
	accountSvc    accountService.AccountService
	consentMgr    AdminConsentManager
	auditQueryMgr AdminAuditQueryManager
	lockoutMgr    AdminLockoutManager
	logger        *zap.Logger
}

// NewAdminController creates a new admin controller instance
func NewAdminController(
	accountSvc accountService.AccountService,
	consentMgr AdminConsentManager,
	auditQueryMgr AdminAuditQueryManager,
	lockoutMgr AdminLockoutManager,
	logger *zap.Logger,
) *AdminController {
	return &AdminController{
		accountSvc:    accountSvc,
		consentMgr:    consentMgr,
		auditQueryMgr: auditQueryMgr,
		lockoutMgr:    lockoutMgr,
		logger:        logger,
	}
}

// RegisterRoutes registers admin routes
func (c *AdminController) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/audit-logs", c.ListAuditLogs)

	accounts := rg.Group("/accounts")
	{
		accounts.GET("", c.ListAccounts)
		accounts.POST("", c.CreateAccount)
		accounts.GET("/:account_id", c.GetAccount)
		accounts.DELETE("/:account_id", c.DeleteAccount)
		accounts.POST("/:account_id/disable", c.DisableAccount)
		accounts.POST("/:account_id/enable", c.EnableAccount)
		accounts.GET("/:account_id/roles", c.GetAccountRoles)
		accounts.POST("/:account_id/roles", c.AddRole)
		accounts.DELETE("/:account_id/roles/:role_id", c.RemoveRole)
		accounts.GET("/:account_id/consents", c.ListConsents)
		accounts.DELETE("/:account_id/consents/:client_id", c.RevokeConsent)
		accounts.GET("/:account_id/lockout", c.GetLockoutStatus)
		accounts.POST("/:account_id/lockout/clear", c.ClearLockout)
		accounts.POST("/:account_id/password", c.ChangePassword)
	}
}

// CreateAccountRequestBody is the request body for administrator-created accounts.
type CreateAccountRequestBody struct {
	Username    string `json:"username" binding:"required,min=2,max=64"`
	DisplayName string `json:"display_name" binding:"required,max=255"`
	Email       string `json:"email" binding:"omitempty,email,max=254"`
	Phone       string `json:"phone" binding:"omitempty,max=32"`
	Password    string `json:"password" binding:"required,min=12,max=72"`
	Locale      string `json:"locale" binding:"omitempty,max=10"`
	Timezone    string `json:"timezone" binding:"omitempty,max=64"`
}

// CreateAccount POST /api/admin/accounts
func (c *AdminController) CreateAccount(ctx *gin.Context) {
	var req CreateAccountRequestBody
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}

	if strings.TrimSpace(req.Email) == "" && strings.TrimSpace(req.Phone) == "" {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "email or phone is required"))
		return
	}

	account, err := c.accountSvc.RegisterAccount(ctx, &accountService.RegisterAccountRequest{
		Username:    strings.TrimSpace(req.Username),
		DisplayName: strings.TrimSpace(req.DisplayName),
		Email:       strings.TrimSpace(req.Email),
		Phone:       strings.TrimSpace(req.Phone),
		Password:    req.Password,
		Locale:      strings.TrimSpace(req.Locale),
		Timezone:    strings.TrimSpace(req.Timezone),
	})
	if err != nil {
		if errors.Is(err, accountService.ErrUsernameAlreadyTaken) ||
			errors.Is(err, accountService.ErrEmailAlreadyRegistered) ||
			errors.Is(err, accountService.ErrPhoneAlreadyRegistered) {
			controllerutil.AbortWithServiceError(ctx, c.logger, err, adminCreateAccountErrorMap,
				http.StatusConflict, "failed to create account")
			return
		}
		if strings.Contains(err.Error(), "validation failed") ||
			strings.Contains(err.Error(), "password") ||
			strings.Contains(err.Error(), "username") ||
			strings.Contains(err.Error(), "credential:") ||
			strings.Contains(err.Error(), "account:") ||
			strings.Contains(err.Error(), "invalid timezone") {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		c.logger.Error("Failed to create account", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to create account"))
		return
	}

	ctx.JSON(http.StatusCreated, gouno.NewSuccessResponse(account))
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
//
// Fail-safe: returns true (deny) if the admin ID cannot be determined, to prevent
// self-account operations when the middleware is misconfigured. This applies to ALL
// operations that use this guard (Delete, Disable, Enable, AddRole, RemoveRole),
// not just self-deletion — so a missing admin ID will block every mutation on every
// account, which is the intended fail-closed behavior.
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminAccountErrorMap,
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminDeleteAccountErrorMap,
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminAccountErrorMap,
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminAccountErrorMap,
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminAccountErrorMap,
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminRoleErrorMap,
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
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminRoleErrorMap,
			http.StatusInternalServerError, "Failed to remove role")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("role removed"))
}

// ListConsents GET /api/admin/accounts/:account_id/consents
func (c *AdminController) ListConsents(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	consents, err := c.consentMgr.ListConsentsByAccountID(ctx, accountID)
	if err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminConsentErrorMap,
			http.StatusInternalServerError, "Failed to list consents")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(consents))
}

// RevokeConsent DELETE /api/admin/accounts/:account_id/consents/:client_id
func (c *AdminController) RevokeConsent(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	clientID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("client_id"), "client_id")
	if !ok {
		return
	}

	if err := c.consentMgr.DeleteConsent(ctx, accountID, clientID); err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, adminConsentErrorMap,
			http.StatusInternalServerError, "Failed to revoke consent")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("consent revoked"))
}

// ListAuditLogs GET /api/admin/audit-logs
func (c *AdminController) ListAuditLogs(ctx *gin.Context) {
	var filter auditRepository.AuditQueryFilter

	if accountID := ctx.Query("account_id"); accountID != "" {
		if _, ok := controllerutil.ValidateUUID(ctx, accountID, "account_id"); !ok {
			return
		}
		filter.AccountID = accountID
	}
	filter.EventType = ctx.Query("event_type")

	if startStr := ctx.Query("start_time"); startStr != "" {
		t, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid start_time format, use RFC3339"))
			return
		}
		filter.StartTime = &t
	}
	if endStr := ctx.Query("end_time"); endStr != "" {
		t, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid end_time format, use RFC3339"))
			return
		}
		filter.EndTime = &t
	}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "20"))
	filter.Page = page
	filter.PageSize = pageSize

	records, total, err := c.auditQueryMgr.Query(ctx, filter)
	if err != nil {
		c.logger.Error("Failed to query audit logs", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to query audit logs"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"items":     records,
		"total":     total,
		"page":      filter.Page,
		"page_size": filter.PageSize,
	}))
}

// GetLockoutStatus GET /api/admin/accounts/:account_id/lockout
func (c *AdminController) GetLockoutStatus(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	status, err := c.lockoutMgr.GetLockoutStatus(ctx, accountID)
	if err != nil {
		c.logger.Error("Failed to get lockout status", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to get lockout status"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(status))
}

// ClearLockout POST /api/admin/accounts/:account_id/lockout/clear
func (c *AdminController) ClearLockout(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	if err := c.lockoutMgr.ClearLockout(ctx, accountID); err != nil {
		c.logger.Error("Failed to clear lockout", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to clear lockout"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("lockout cleared"))
}

// ChangePasswordRequest holds password change request body
type ChangePasswordRequest struct {
	NewPassword string `json:"new_password" binding:"required,min=12,max=72"`
}

// ChangePassword POST /api/admin/accounts/:account_id/password
func (c *AdminController) ChangePassword(ctx *gin.Context) {
	accountID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("account_id"), "account_id")
	if !ok {
		return
	}

	if isSelfAccount(ctx, accountID) {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "cannot perform this operation on your own account"))
		return
	}

	var req ChangePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body or password too short/long"))
		return
	}

	if err := c.accountSvc.AdminChangePassword(ctx, accountID, req.NewPassword); err != nil {
		c.logger.Error("Failed to change user password", zap.String("account_id", accountID), zap.Error(err))
		if errors.Is(err, accountService.ErrAccountNotActive) {
			ctx.JSON(http.StatusConflict, gouno.NewErrorResponse(http.StatusConflict, err.Error()))
			return
		}
		if strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "hash") {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to change password"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("password changed successfully"))
}
