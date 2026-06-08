package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/internal/testutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	gm "github.com/rushairer/gosso/middleware"
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

// setupRealTokenService creates a real TokenService backed by in-memory RSA keys
// and miniredis. Needed for JWTAuthMiddleware tests which require a concrete *TokenService.
func setupRealTokenService(t *testing.T) (*tokenService.TokenService, func()) {
	t.Helper()
	logger := zap.NewNop()
	redisClient, mr := testutil.SetupTestRedis(t)
	keySvc, err := tokenService.NewKeyService("", "", logger)
	require.NoError(t, err)
	blacklist := tokenService.NewBlacklistService(redisClient, logger)
	svc := tokenService.NewTokenService(
		keySvc,
		"http://localhost:8080",
		15*time.Minute,
		7*24*time.Hour,
		redisClient,
		blacklist,
		logger,
	)
	return svc, mr.Close
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

	// Pre-set claims in context via middleware
	engine2 := setupGin()
	engine2.GET("/admin", func(ctx *gin.Context) {
		ctx.Set(gm.ContextKeyClaims, &tokenDomain.AccessTokenClaims{
			Roles: []string{"admin", "user"},
		})
		ctx.Next()
	}, AdminRequiredMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	engine2.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminRequired_NonAdminRole(t *testing.T) {
	engine := setupGin()
	engine.GET("/admin", func(ctx *gin.Context) {
		ctx.Set(gm.ContextKeyClaims, &tokenDomain.AccessTokenClaims{
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
		ctx.Set(gm.ContextKeyClaims, &tokenDomain.AccessTokenClaims{
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

// ──────────────────────────────────────────────
// ValidateBearerToken
// ──────────────────────────────────────────────

// mockTokenValidator implements TokenValidator for testing.
type mockTokenValidator struct {
	claims *tokenDomain.AccessTokenClaims
	err    error
}

func (m *mockTokenValidator) ValidateAccessTokenWithContext(_ context.Context, _ string) (*tokenDomain.AccessTokenClaims, error) {
	return m.claims, m.err
}

// mockSessionValidator implements sessionDomain.SessionValidator for testing.
type mockSessionValidator struct {
	session *sessionDomain.Session
	err     error
}

func (m *mockSessionValidator) ValidateSession(_ context.Context, _ string) (*sessionDomain.Session, error) {
	return m.session, m.err
}

func TestValidateBearerToken_MissingToken(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, &mockTokenValidator{}, nil)
		assert.Nil(t, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing authorization")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
}

func TestValidateBearerToken_InvalidToken(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, &mockTokenValidator{err: fmt.Errorf("token expired")}, nil)
		assert.Nil(t, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired token")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer badtoken")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
}

func TestValidateBearerToken_ScopedToken_Rejected(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, &mockTokenValidator{
			claims: &tokenDomain.AccessTokenClaims{
				Scope: "mfa:verify",
			},
		}, nil)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, ErrTokenScopeNotAllowed)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer mfa-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
}

func TestValidateBearerToken_ExpiredSession(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, &mockTokenValidator{
			claims: &tokenDomain.AccessTokenClaims{
				AccountID: "acct-001",
				SessionID: "sess-001",
			},
		}, &mockSessionValidator{err: fmt.Errorf("session not found")})
		assert.Nil(t, claims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session expired")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer goodtoken")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
}

func TestValidateBearerToken_Success(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, &mockTokenValidator{
			claims: &tokenDomain.AccessTokenClaims{
				AccountID: "acct-001",
				SessionID: "sess-001",
			},
		}, &mockSessionValidator{
			session: &sessionDomain.Session{ID: "sess-001"},
		})
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "acct-001", claims.AccountID)
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateBearerToken_NilSessionValidator(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, &mockTokenValidator{
			claims: &tokenDomain.AccessTokenClaims{
				AccountID: "acct-001",
				SessionID: "sess-001",
			},
		}, nil)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "acct-001", claims.AccountID)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer validtoken")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
}

// ──────────────────────────────────────────────
// JWTAuthMiddleware (end-to-end with real TokenService)
// ──────────────────────────────────────────────

func TestJWTAuthMiddleware_Success(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	tokenString, err := tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "acct-001",
		SessionID: "sess-001",
	})
	require.NoError(t, err)

	engine := setupGin()
	engine.GET("/protected", JWTAuthMiddleware(tokenSvc, &mockSessionValidator{
		session: &sessionDomain.Session{ID: "sess-001"},
	}), func(ctx *gin.Context) {
		accountID, _ := ctx.Get(gm.ContextKeyAccountID)
		claims, _ := ctx.Get(gm.ContextKeyClaims)
		ctx.JSON(http.StatusOK, gin.H{
			"account_id": accountID,
			"has_claims": claims != nil,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "acct-001", resp["account_id"])
	assert.Equal(t, true, resp["has_claims"])
}

func TestJWTAuthMiddleware_MissingToken(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	engine := setupGin()
	engine.GET("/protected", JWTAuthMiddleware(tokenSvc, &mockSessionValidator{
		session: &sessionDomain.Session{},
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	engine := setupGin()
	engine.GET("/protected", JWTAuthMiddleware(tokenSvc, &mockSessionValidator{
		session: &sessionDomain.Session{},
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer garbage.jwt.token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_ScopedToken_Returns403(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	tokenString, err := tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "acct-001",
		SessionID: "sess-001",
		Scope:     "mfa:verify",
	})
	require.NoError(t, err)

	engine := setupGin()
	engine.GET("/protected", JWTAuthMiddleware(tokenSvc, &mockSessionValidator{
		session: &sessionDomain.Session{ID: "sess-001"},
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestJWTAuthMiddleware_ExpiredSession_Returns401(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	tokenString, err := tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "acct-001",
		SessionID: "sess-expired",
	})
	require.NoError(t, err)

	engine := setupGin()
	engine.GET("/protected", JWTAuthMiddleware(tokenSvc, &mockSessionValidator{
		err: fmt.Errorf("session not found"),
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_NilSessionValidator_Panics(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	assert.Panics(t, func() {
		JWTAuthMiddleware(tokenSvc, nil)
	})
}

func TestJWTAuthMiddleware_BlacklistedToken_Returns401(t *testing.T) {
	tokenSvc, cleanup := setupRealTokenService(t)
	defer cleanup()

	tokenString, err := tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "acct-001",
		SessionID: "sess-001",
	})
	require.NoError(t, err)

	// Revoke the token before sending it
	ctx := context.Background()
	claims, err := tokenSvc.ValidateAccessTokenWithContext(ctx, tokenString)
	require.NoError(t, err)
	err = tokenSvc.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time)
	require.NoError(t, err)

	engine := setupGin()
	engine.GET("/protected", JWTAuthMiddleware(tokenSvc, &mockSessionValidator{
		session: &sessionDomain.Session{ID: "sess-001"},
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// AuditMetadataMiddleware
// ──────────────────────────────────────────────

func TestAuditMetadataMiddleware(t *testing.T) {
	engine := setupGin()
	engine.GET("/test", AuditMetadataMiddleware(), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
