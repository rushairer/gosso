package controller

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// TokenManager defines the token operations needed by the OAuth2 controller.
type TokenManager interface {
	GenerateAccessToken(claims *tokenDomain.AccessTokenClaims) (string, error)
	GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*tokenDomain.RefreshToken, error)
	ValidateRefreshToken(ctx context.Context, token string) (*tokenDomain.RefreshToken, error)
	ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*tokenDomain.AccessTokenClaims, error)
	RotateRefreshToken(ctx context.Context, oldToken string) (*tokenDomain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error)
	AccessExpiry() time.Duration
}

// DeviceCodeManager defines the device code operations needed by the OAuth2 controller.
type DeviceCodeManager interface {
	CreateDeviceCode(ctx context.Context, clientID string, scopes []string) (*oauth2Domain.DeviceCode, error)
	GetDeviceCode(ctx context.Context, deviceCode string) (*oauth2Domain.DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*oauth2Domain.DeviceCode, error)
	AuthorizeDeviceCode(ctx context.Context, deviceCode, accountID string) error
	DenyDeviceCode(ctx context.Context, deviceCode string) error
	CheckAndUpdatePollRate(ctx context.Context, deviceCode string) error
	ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string) (*oauth2Domain.DeviceCode, error)
}

// AccountValidator checks whether an account exists and is active.
type AccountValidator interface {
	IsAccountActive(ctx context.Context, accountID string) bool
}

//go:embed template/consent.html
var consentTemplateFS embed.FS

//go:embed template/device.html
var deviceTemplateFS embed.FS

// OAuth2Controller handles OAuth2 protocol endpoints.
type OAuth2Controller struct {
	clientSvc        oauth2Service.OAuth2ClientService
	authCodeSvc      *oauth2Service.AuthCodeService
	consentSvc       *oauth2Service.ConsentService
	tokenSvc         TokenManager
	idTokenSvc       *oidcService.IDTokenService
	deviceCodeSvc    DeviceCodeManager
	clientAuth       oauth2Service.ClientAuthenticator
	accountValidator AccountValidator
	sessionValidator sessionDomain.SessionValidator
	issuer           string
	consentTmpl      *template.Template
	deviceTmpl       *template.Template
	logger           *zap.Logger
}

// NewOAuth2Controller creates a new OAuth2 controller instance.
func NewOAuth2Controller(
	clientSvc oauth2Service.OAuth2ClientService,
	authCodeSvc *oauth2Service.AuthCodeService,
	consentSvc *oauth2Service.ConsentService,
	tokenSvc TokenManager,
	idTokenSvc *oidcService.IDTokenService,
	deviceCodeSvc DeviceCodeManager,
	accountValidator AccountValidator,
	sessionValidator sessionDomain.SessionValidator,
	issuer string,
	logger *zap.Logger,
) (*OAuth2Controller, error) {
	consentTmpl, err := template.ParseFS(consentTemplateFS, "template/consent.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse consent template: %w", err)
	}
	deviceTmpl, err := template.ParseFS(deviceTemplateFS, "template/device.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse device template: %w", err)
	}
	return &OAuth2Controller{
		clientSvc:        clientSvc,
		authCodeSvc:      authCodeSvc,
		consentSvc:       consentSvc,
		tokenSvc:         tokenSvc,
		idTokenSvc:       idTokenSvc,
		deviceCodeSvc:    deviceCodeSvc,
		clientAuth:       oauth2Service.ClientAuthenticator{},
		accountValidator: accountValidator,
		sessionValidator: sessionValidator,
		issuer:           issuer,
		consentTmpl:      consentTmpl,
		deviceTmpl:       deviceTmpl,
		logger:           logger,
	}, nil
}

// authenticateRequest extracts and validates the access token from the Authorization header.
// Returns the account ID on success, or an empty string and writes an error response on failure.
//
// This intentionally duplicates JWTAuthMiddleware logic because OAuth2 endpoints
// need inline authentication within handler methods (e.g. consent, device authorization)
// rather than pre-handler middleware — the same endpoint may serve both authenticated
// and unauthenticated flows.
func (c *OAuth2Controller) authenticateRequest(ctx *gin.Context) (string, bool) {
	tokenString := ""
	if authHeader := ctx.GetHeader("Authorization"); authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			tokenString = parts[1]
		}
	}
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}

	claims, err := c.tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}
	if claims.Scope != "" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "scoped token not allowed"})
		return "", false
	}
	if c.sessionValidator != nil && claims.SessionID != "" {
		if _, err := c.sessionValidator.ValidateSession(ctx.Request.Context(), claims.SessionID); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return "", false
		}
	}
	return claims.AccountID, true
}

// RegisterRoutes registers OAuth2 routes.
// introspectLimit and deviceCodeLimit are optional rate limit middleware for CPU-intensive endpoints.
func (c *OAuth2Controller) RegisterRoutes(rg *gin.RouterGroup, authMiddleware, introspectLimit, deviceCodeLimit gin.HandlerFunc) {
	rg.GET("/authorize", authMiddleware, c.Authorize)
	rg.POST("/authorize", c.SubmitConsent)
	rg.POST("/token", c.Token)
	rg.POST("/revoke", authMiddleware, c.Revoke)

	introspectHandlers := []gin.HandlerFunc{c.Introspect}
	if introspectLimit != nil {
		introspectHandlers = []gin.HandlerFunc{introspectLimit, c.Introspect}
	}
	rg.POST("/introspect", introspectHandlers...)

	deviceCodeHandlers := []gin.HandlerFunc{c.DeviceCodeRequest}
	if deviceCodeLimit != nil {
		deviceCodeHandlers = []gin.HandlerFunc{deviceCodeLimit, c.DeviceCodeRequest}
	}
	rg.POST("/device/code", deviceCodeHandlers...)

	rg.GET("/device", authMiddleware, c.DeviceUserPage)
	rg.POST("/device", c.DeviceUserSubmit)
}

func redirectWithCode(ctx *gin.Context, redirectURI, code, state string) {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}
	params := parsedURL.Query()
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	parsedURL.RawQuery = params.Encode()
	ctx.Redirect(http.StatusFound, parsedURL.String())
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	var result []string
	for _, s := range strings.Split(scope, " ") {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// intersectScopes returns the scopes present in both requested and allowed.
func intersectScopes(requested, allowed []string) []string {
	var result []string
	for _, s := range requested {
		if slices.Contains(allowed, s) {
			result = append(result, s)
		}
	}
	return result
}

// csrfTokenFromCookie reads the CSRF token from the request cookie for server-side template injection.
func csrfTokenFromCookie(ctx *gin.Context) string {
	cookie, _ := ctx.Cookie("csrf_token")
	return cookie
}
