package controller

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// ForgotPassword tests
// ──────────────────────────────────────────────

func TestForgotPassword_InvalidEmail(t *testing.T) {
	// Note: ForgotPassword tests that call through to passwordResetSvc are skipped
	// because PasswordResetService is a concrete type (not interface-injected).
	// Validation-only tests that fail before reaching the service are safe.
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"email":"not-an-email"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestForgotPassword_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestForgotPassword_NonexistentEmail(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByTypeAndIdentifierFn: func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
			return nil, accountRepo.ErrCredentialNotFound
		},
	}
	emailSender := &mockPasswordResetEmailSender{}
	accountSvc := &mockAccountServiceForSocial{}
	engine := setupAuthControllerWithPasswordResetSvc(t, credRepo, emailSender, accountSvc)

	body := `{"email":"nonexistent@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Always 200 to prevent email enumeration
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestForgotPassword_Success(t *testing.T) {
	accountID := "account-001"
	userEmail := "user@example.com"

	credRepo := &mockCredentialRepoForController{
		findByTypeAndIdentifierFn: func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
			cred := &accountDomain.Credential{
				ID:         "cred-001",
				AccountID:  accountID,
				Type:       accountDomain.CredentialTypeEmail,
				Identifier: &userEmail,
			}
			return cred, nil
		},
	}

	activeAccount, _ := accountDomain.NewAccount("Test User")
	activeAccount.ID = accountID

	accountSvc := &mockAccountServiceForSocial{
		findAccountByIDFn: func(_ context.Context, id string) (*accountDomain.Account, error) {
			if id == accountID {
				return activeAccount, nil
			}
			return nil, fmt.Errorf("not found")
		},
	}

	resetEmailSent := false
	emailSender := &mockPasswordResetEmailSender{
		sendFn: func(_ context.Context, to, resetLink string) error {
			assert.Equal(t, userEmail, to)
			assert.Contains(t, resetLink, "https://app.example.com/reset#token=")
			resetEmailSent = true
			return nil
		},
	}

	engine := setupAuthControllerWithPasswordResetSvc(t, credRepo, emailSender, accountSvc)

	body := `{"email":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, resetEmailSent, "password reset email sender should have been called")
}

// ──────────────────────────────────────────────
// ResetPassword tests
// ──────────────────────────────────────────────

func TestResetPassword_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_ShortPassword(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	// Password "short" is 5 chars, below the binding tag min=12
	body := `{"token":"some-token","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestResetPassword_InvalidToken(t *testing.T) {
	credRepo := &mockCredentialRepoForController{}
	emailSender := &mockPasswordResetEmailSender{}
	accountSvc := &mockAccountServiceForSocial{}
	engine := setupAuthControllerWithPasswordResetSvc(t, credRepo, emailSender, accountSvc)

	// Password meets ValidatePasswordStrength; token is not present in Redis.
	body := `{"token":"fake-invalid-token-abc123","new_password":"ValidP@ssw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired reset token")
}

// ──────────────────────────────────────────────
// ChangePassword tests
// ──────────────────────────────────────────────

func TestChangePassword_Success(t *testing.T) {
	passwordChanged := false
	authSvc := &mockAuthOrchestrator{
		verifyPasswordFn: func() error {
			return nil
		},
		changePasswordFn: func(oldPassword, newPassword string) error {
			assert.Equal(t, "oldPassword123!", oldPassword)
			assert.Equal(t, "newPassword123!", newPassword)
			passwordChanged = true
			return nil
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"current_password":"oldPassword123!","new_password":"newPassword123!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/change", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, passwordChanged)
}

func TestChangePassword_InvalidCurrentPassword(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		verifyPasswordFn: func() error {
			return fmt.Errorf("incorrect password")
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"current_password":"wrongPassword!","new_password":"newPassword123!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/change", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "incorrect current password")
}

func TestChangePassword_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	// Password too short (requires min 12 characters as defined in binding)
	body := `{"current_password":"oldPassword123!","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/change", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangePassword_ValidationError(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		verifyPasswordFn: func() error {
			return nil
		},
		changePasswordFn: func(oldPassword, newPassword string) error {
			return fmt.Errorf("password must contain uppercase, lowercase, digit, and special character")
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"current_password":"oldPassword123!","new_password":"newPassword123!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/change", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "password must contain uppercase, lowercase, digit, and special character")
}
