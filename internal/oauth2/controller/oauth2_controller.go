package controller

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	authMiddleware "github.com/rushairer/gosso/internal/auth/middleware"
	"github.com/rushairer/gosso/internal/cache"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
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
	RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error
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
	ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string, clientID string) (*oauth2Domain.DeviceCode, error)
}

// AuthCodeManager defines authorization code generation and validation operations.
type AuthCodeManager interface {
	ValidateCode(ctx context.Context, code, clientID, redirectURI string, codeVerifier *string) (*oauth2Domain.AuthorizationCode, error)
	GenerateCode(ctx context.Context, clientID, accountID, redirectURI string, scopes []string, codeChallenge, codeChallengeMethod, nonce string) (*oauth2Domain.AuthorizationCode, error)
}

// ConsentManager defines user consent persistence and retrieval operations.
type ConsentManager interface {
	GetConsent(ctx context.Context, accountID, clientID string) (*oauth2Domain.Consent, error)
	SaveConsent(ctx context.Context, consent *oauth2Domain.Consent) error
}

// IDTokenManager defines OIDC ID token generation operations.
type IDTokenManager interface {
	GenerateIDToken(ctx context.Context, accountID, clientID string, scopes []string, nonce string, authTime time.Time, accessToken string, authMethods []string) (string, error)
}

// ClientAuthManager defines OAuth2 client credential verification operations.
type ClientAuthManager interface {
	AuthenticateClient(client *oauth2Domain.OAuth2Client, clientSecret string) error
	// DummyAuthenticate performs a dummy bcrypt comparison to mitigate timing side-channels
	// when client lookup fails, making the response time indistinguishable from a failed auth.
	DummyAuthenticate()
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
	authCodeSvc      AuthCodeManager
	consentSvc       ConsentManager
	tokenSvc         TokenManager
	idTokenSvc       IDTokenManager
	deviceCodeSvc    DeviceCodeManager
	clientAuth       ClientAuthManager
	accountValidator AccountValidator
	sessionValidator sessionDomain.SessionValidator
	redis            *cache.RedisClient
	issuer           string
	consentTmpl      *template.Template
	deviceTmpl       *template.Template
	logger           *zap.Logger
}

// NewOAuth2Controller creates a new OAuth2 controller instance.
func NewOAuth2Controller(
	clientSvc oauth2Service.OAuth2ClientService,
	authCodeSvc AuthCodeManager,
	consentSvc ConsentManager,
	tokenSvc TokenManager,
	idTokenSvc IDTokenManager,
	deviceCodeSvc DeviceCodeManager,
	clientAuth ClientAuthManager,
	accountValidator AccountValidator,
	sessionValidator sessionDomain.SessionValidator,
	redis *cache.RedisClient,
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
		clientAuth:       clientAuth,
		accountValidator: accountValidator,
		sessionValidator: sessionValidator,
		redis:            redis,
		issuer:           issuer,
		consentTmpl:      consentTmpl,
		deviceTmpl:       deviceTmpl,
		logger:           logger,
	}, nil
}

// authenticateRequest extracts and validates the access token from the Authorization header.
// Returns the account ID on success, or an empty string and writes an error response on failure.
//
// This uses ValidateBearerToken from auth/middleware for the shared validation logic,
// but serves inline within handler methods because OAuth2 endpoints may serve both
// authenticated and unauthenticated flows on the same route.
func (c *OAuth2Controller) authenticateRequest(ctx *gin.Context) (string, bool) {
	claims, err := authMiddleware.ValidateBearerToken(ctx, c.tokenSvc, c.sessionValidator)
	if err != nil {
		if errors.Is(err, authMiddleware.ErrTokenScopeNotAllowed) {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "insufficient scope"})
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "invalid or expired token"})
		}
		return "", false
	}
	return claims.AccountID, true
}

// RegisterRoutes registers OAuth2 routes.
// Rate limit middleware arguments are optional and applied per endpoint.
func (c *OAuth2Controller) RegisterRoutes(rg *gin.RouterGroup, authMiddleware, tokenLimit, introspectLimit, deviceCodeLimit, deviceUserLimit gin.HandlerFunc) {
	rg.GET("/authorize", authMiddleware, c.Authorize)
	rg.POST("/authorize", authMiddleware, c.SubmitConsent)

	tokenHandlers := []gin.HandlerFunc{c.Token}
	if tokenLimit != nil {
		tokenHandlers = []gin.HandlerFunc{tokenLimit, c.Token}
	}
	rg.POST("/token", tokenHandlers...)
	revokeHandlers := []gin.HandlerFunc{c.Revoke}
	if tokenLimit != nil {
		revokeHandlers = []gin.HandlerFunc{tokenLimit, c.Revoke}
	}
	rg.POST("/revoke", revokeHandlers...)

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
	deviceUserHandlers := []gin.HandlerFunc{c.DeviceUserSubmit}
	if deviceUserLimit != nil {
		deviceUserHandlers = []gin.HandlerFunc{deviceUserLimit, c.DeviceUserSubmit}
	}
	rg.POST("/device", deviceUserHandlers...)
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
	cookie, _ := ctx.Cookie("__Host-csrf_token")
	if cookie == "" {
		cookie, _ = ctx.Cookie("csrf_token")
	}
	return cookie
}
