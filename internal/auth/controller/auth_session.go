package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/controllerutil"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	utility "github.com/rushairer/gosso/internal/utility"
)

// revokeSessionErrorMap maps session revocation errors to HTTP responses.
var revokeSessionErrorMap = []controllerutil.ErrorRule{
	{Sentinel: sessionService.ErrSessionAccessDenied, Mapping: controllerutil.ErrorMapping{Status: http.StatusForbidden, Message: "session not found or access denied"}},
}

// Logout POST /api/auth/logout
func (c *AuthController) Logout(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	accessTokenJTI := tc.ID
	var tokenExpiresAt time.Time
	if tc.ExpiresAt != nil {
		tokenExpiresAt = tc.ExpiresAt.Time
	}

	if err := c.authSvc.Logout(ctx, tc.AccountID, tc.SessionID, accessTokenJTI, tokenExpiresAt); err != nil {
		c.logger.Error("Logout error", zap.String("account_id", utility.MaskOpaqueID(tc.AccountID)), zap.String("session_id", utility.MaskOpaqueID(tc.SessionID)), zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout incomplete"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("logged out"))
}

// GetSession GET /api/auth/session
func (c *AuthController) GetSession(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	session, err := c.authSvc.ValidateSession(ctx, tc.SessionID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "session invalid"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(session))
}

// ListSessions GET /api/auth/sessions
func (c *AuthController) ListSessions(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	sessions, err := c.authSvc.ListSessions(ctx, tc.AccountID)
	if err != nil {
		c.logger.Error("Failed to list sessions", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to list sessions"))
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(sessions))
}

// RevokeSession DELETE /api/auth/sessions/:id
func (c *AuthController) RevokeSession(ctx *gin.Context) {
	tc, ok := getClaimsFromContext(ctx)
	if !ok {
		return
	}

	sessionID, ok := controllerutil.ValidateUUID(ctx, ctx.Param("id"), "session_id")
	if !ok {
		return
	}

	// Do not allow revoking the current session (should use logout)
	if sessionID == tc.SessionID {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "use /logout to revoke current session"))
		return
	}

	if err := c.authSvc.RevokeSession(ctx, tc.AccountID, sessionID); err != nil {
		controllerutil.AbortWithServiceError(ctx, c.logger, err, revokeSessionErrorMap,
			http.StatusInternalServerError, "Failed to revoke session")
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"revoked": true}))
}
