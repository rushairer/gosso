package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"

	"github.com/rushairer/gosso/internal/site"
	"github.com/rushairer/gosso/middleware"
)

// GetPublicSiteBranding is deliberately unauthenticated: the SPA needs it before login.
func (c *AdminController) GetPublicSiteBranding(ctx *gin.Context) {
	settings, err := c.getSiteSettings(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to load site branding"))
		return
	}
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(settings.PublicBranding()))
}

func (c *AdminController) GetSiteSettings(ctx *gin.Context) {
	settings, err := c.getSiteSettings(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to load site settings"))
		return
	}
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(settings))
}

func (c *AdminController) UpdateSiteSettings(ctx *gin.Context) {
	if c.siteSettingsSvc == nil {
		ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "site settings unavailable"))
		return
	}
	var request site.Settings
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request body"))
		return
	}
	updated, err := c.siteSettingsSvc.Update(ctx, request, ctx.GetString(middleware.ContextKeyAccountID))
	if err != nil {
		if errors.Is(err, site.ErrInvalidSettings) {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to update site settings"))
		return
	}
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(updated))
}

func (c *AdminController) GetSecurityPolicy(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{
		"session_ttl":                   c.authConfig.SessionTTL.String(),
		"max_sessions":                  c.authConfig.MaxSessions,
		"max_session_age":               c.authConfig.MaxSessionAge.String(),
		"access_token_expiry":           c.authConfig.AccessTokenExpiry.String(),
		"refresh_token_expiry":          c.authConfig.RefreshTokenExpiry.String(),
		"id_token_expiry":               c.authConfig.IDTokenExpiry.String(),
		"enforce_ip_binding":            c.authConfig.EnforceIPBinding,
		"enforce_pkce_for_confidential": c.authConfig.EnforcePKCEForConfidential,
		"login_max_attempts":            c.authConfig.LoginMaxAttempts,
		"login_rate_limit_window":       c.authConfig.LoginRateLimitWindow.String(),
		"mfa_account_max_attempts":      c.authConfig.MFAAccountMaxAttempts,
		"mfa_account_rate_limit_window": c.authConfig.MFAAccountRateLimitWindow.String(),
		"password_reset_token_ttl":      c.authConfig.PasswordResetTokenTTL.String(),
		"webauthn_enabled":              c.authConfig.WebAuthnRPID != "" && c.authConfig.WebAuthnRPOrigin != "",
	}))
}

func (c *AdminController) getSiteSettings(ctx *gin.Context) (site.Settings, error) {
	if c.siteSettingsSvc == nil {
		return site.DefaultSettings(), nil
	}
	return c.siteSettingsSvc.Get(ctx)
}
