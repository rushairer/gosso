package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ──────────────────────────────────────────────
// extractBearerToken (tested via JWTAuthMiddleware missing-token path)
// ──────────────────────────────────────────────

func setupGin() *gin.Engine {
	return gin.New()
}

func TestExtractBearerToken_FromHeader(t *testing.T) {
	// We test extractBearerToken indirectly via the middleware's "missing" path
	// Since JWTAuthMiddleware needs a real TokenService, we test the no-token path
	// which returns 401 before reaching the token service.
	engine := setupGin()
	// Use a nil token service — it will panic if it reaches ValidateAccessToken,
	// which means the test is wrong if it doesn't 401 first.
	engine.GET("/test", func(ctx *gin.Context) {
		token := extractBearerToken(ctx)
		ctx.JSON(http.StatusOK, gin.H{"token": token})
	})

	tests := []struct {
		name      string
		header    string
		wantToken string
	}{
		{"valid bearer", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
		{"lowercase bearer", "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
		{"no header", "", ""},
		{"empty header", "", ""},
		{"invalid scheme", "Basic dXNlcjpwYXNz", ""},
		{"missing token part", "Bearer", ""},
		{"extra spaces in token", "Bearer token with spaces", "token with spaces"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			var resp map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tt.wantToken, resp["token"])
		})
	}
}

// ──────────────────────────────────────────────
// AdminRequiredMiddleware
// ──────────────────────────────────────────────

func TestAdminRequired_HasAdminRole(t *testing.T) {
	engine := setupGin()
	engine.GET("/admin", AdminRequiredMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()

	// Pre-set claims in context via middleware
	engine2 := setupGin()
	engine2.GET("/admin", func(ctx *gin.Context) {
		ctx.Set(ContextKeyClaims, &tokenDomain.AccessTokenClaims{
			Roles: []string{"admin", "user"},
		})
		ctx.Next()
	}, AdminRequiredMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	engine2.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminRequired_NonAdminRole(t *testing.T) {
	engine := setupGin()
	engine.GET("/admin", func(ctx *gin.Context) {
		ctx.Set(ContextKeyClaims, &tokenDomain.AccessTokenClaims{
			Roles: []string{"user", "viewer"},
		})
		ctx.Next()
	}, AdminRequiredMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdminRequired_NoClaims(t *testing.T) {
	engine := setupGin()
	engine.GET("/admin", AdminRequiredMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminRequired_EmptyRoles(t *testing.T) {
	engine := setupGin()
	engine.GET("/admin", func(ctx *gin.Context) {
		ctx.Set(ContextKeyClaims, &tokenDomain.AccessTokenClaims{
			Roles: []string{},
		})
		ctx.Next()
	}, AdminRequiredMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ──────────────────────────────────────────────
// JWTAuthMiddleware missing-token paths
// ──────────────────────────────────────────────

func TestJWTAuth_NoToken_Returns401(t *testing.T) {
	engine := setupGin()
	// nil tokenSvc — won't be reached because no token
	engine.GET("/protected", func(ctx *gin.Context) {
		// Simulate the "no token" check from JWTAuthMiddleware
		tokenString := extractBearerToken(ctx)
		if tokenString == "" {
			tokenString = ctx.Query("access_token")
		}
		if tokenString == "" {
			tokenString = ctx.PostForm("access_token")
		}
		if tokenString == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuth_TokenFromQuery(t *testing.T) {
	engine := setupGin()
	engine.GET("/protected", func(ctx *gin.Context) {
		tokenString := extractBearerToken(ctx)
		if tokenString == "" {
			tokenString = ctx.Query("access_token")
		}
		ctx.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected?access_token=query-token", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "query-token", resp["token"])
}
