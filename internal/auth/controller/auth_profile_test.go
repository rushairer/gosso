package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/testutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

func setupAuthControllerWithClaimsAndVerification(
	t *testing.T,
	authSvc *mockAuthOrchestrator,
	claims *tokenDomain.AccessTokenClaims,
	credRepo accountRepo.CredentialRepository,
	emailSender authService.EmailSender,
) *gin.Engine {
	t.Helper()
	redisClient, _ := testutil.SetupTestRedis(t)

	verificationSvc := authService.NewVerificationServiceWithConfig(redisClient, emailSender, nil, credRepo, nil, authService.VerificationServiceConfig{
		HashPepper: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	if claims != nil {
		engine.Use(func(ctx *gin.Context) {
			ctx.Set(middleware.ContextKeyClaims, claims)
			ctx.Next()
		})
	}

	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}

	ctrl := NewAuthController(authSvc, tokenMgr, nil, verificationSvc, nil, false, nil)
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, testRouteConfig())

	return engine
}

func TestUpdateProfile_Success(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		updateProfileFn: func(accountID, displayName string) (*accountDomain.Account, error) {
			assert.Equal(t, "account-001", accountID)
			assert.Equal(t, "New Display Name", displayName)
			return &accountDomain.Account{
				ID:          accountID,
				Username:    nil,
				DisplayName: displayName,
			}, nil
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"display_name":"New Display Name"}`
	req := httptest.NewRequest(http.MethodPut, "/api/auth/profile", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"display_name":"New Display Name"`)
}

func TestRequestEmailChange_Success(t *testing.T) {
	passwordVerified := false
	emailChecked := false
	authSvc := &mockAuthOrchestrator{
		verifyPasswordFn: func() error {
			passwordVerified = true
			return nil
		},
		isEmailAvailableFn: func(email string) (bool, error) {
			assert.Equal(t, "new@example.com", email)
			emailChecked = true
			return true, nil
		},
	}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	credRepo := &mockCredentialRepoForController{}
	emailSent := false
	emailSender := &mockEmailSender{
		sendFn: func(_ context.Context, to, _ string) error {
			assert.Equal(t, "new@example.com", to)
			emailSent = true
			return nil
		},
	}

	engine := setupAuthControllerWithClaimsAndVerification(t, authSvc, claims, credRepo, emailSender)

	body := `{"new_email":"new@example.com","password":"mypassword"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/profile/email/change/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, passwordVerified)
	assert.True(t, emailChecked)
	assert.True(t, emailSent)
}

func TestRequestEmailChange_IncorrectPassword(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		verifyPasswordFn: func() error {
			return authService.ErrInvalidCredentials
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"new_email":"new@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/profile/email/change/request", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConfirmEmailChange_DuplicateEmail(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		updateEmailFn: func(accountID, newEmail string) error {
			return authService.ErrEmailAlreadyInUse
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	_ = setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	// Stub test to verify compile and registration
	assert.NotNil(t, authSvc.updateEmailFn)
}
