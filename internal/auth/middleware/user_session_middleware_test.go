package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	gm "github.com/rushairer/gosso/middleware"
)

func TestUserSessionRequiredMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		claims     any
		setClaims  bool
		wantStatus int
		wantBody   string
	}{
		{name: "missing claims", wantStatus: http.StatusUnauthorized, wantBody: "missing authorization"},
		{name: "wrong claims type", setClaims: true, claims: "not-claims", wantStatus: http.StatusInternalServerError, wantBody: "invalid claims type"},
		{
			name:      "delegated user rejected",
			setClaims: true,
			claims: &tokenDomain.AccessTokenClaims{
				AccountID:     "account-1",
				ClientID:      "client-1",
				PrincipalType: tokenDomain.PrincipalTypeDelegatedUser,
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "user session required",
		},
		{
			name:      "machine client rejected",
			setClaims: true,
			claims: &tokenDomain.AccessTokenClaims{
				ClientID:      "machine-client",
				PrincipalType: tokenDomain.PrincipalTypeClient,
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "user session required",
		},
		{
			name:      "user without live session rejected",
			setClaims: true,
			claims: &tokenDomain.AccessTokenClaims{
				AccountID:     "account-1",
				PrincipalType: tokenDomain.PrincipalTypeUserSession,
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "user session required",
		},
		{
			name:      "first party user session accepted",
			setClaims: true,
			claims: &tokenDomain.AccessTokenClaims{
				AccountID:     "account-1",
				SessionID:     "session-1",
				PrincipalType: tokenDomain.PrincipalTypeUserSession,
			},
			wantStatus: http.StatusOK,
			wantBody:   "account-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := gin.New()
			engine.GET("/test", func(ctx *gin.Context) {
				if tt.setClaims {
					ctx.Set(gm.ContextKeyClaims, tt.claims)
				}
				ctx.Next()
			}, UserSessionRequiredMiddleware(), func(ctx *gin.Context) {
				accountID, _ := ctx.Get(gm.ContextKeyAccountID)
				ctx.String(http.StatusOK, "%v", accountID)
			})

			w := httptest.NewRecorder()
			engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantBody)
		})
	}
}
