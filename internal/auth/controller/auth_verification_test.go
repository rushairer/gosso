package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// SendVerification tests
// ──────────────────────────────────────────────

func TestSendVerification_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSendVerification_InvalidType(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"sms","identifier":"1234567890"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "type must be")
}

func TestSendVerification_InvalidEmail(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"email","identifier":"not-an-email"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid email")
}

func TestSendVerification_ValidEmailNoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"email","identifier":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSendVerification_InvalidPhone(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"phone","identifier":"not-a-phone"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid phone format")
}

func TestSendVerification_PhoneNotImplemented(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"phone","identifier":"+12345678901"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "phone verification is not yet supported")
}

func TestSendVerification_CredentialNotOwned(t *testing.T) {
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	// Credential repo returns email credentials for account-001, but none match "user@example.com"
	otherEmail := "other@example.com"
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeEmail: {
				{ID: "cred-001", AccountID: "account-001", Type: accountDomain.CredentialTypeEmail, Identifier: &otherEmail},
			},
		},
	}

	emailSender := &mockEmailSender{}
	engine := setupAuthControllerWithVerificationSvc(t, claims, credRepo, emailSender)

	body := `{"type":"email","identifier":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request")
}

func TestSendVerification_Success(t *testing.T) {
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	userEmail := "user@example.com"
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeEmail: {
				{ID: "cred-001", AccountID: "account-001", Type: accountDomain.CredentialTypeEmail, Identifier: &userEmail},
			},
		},
	}

	emailSent := false
	emailSender := &mockEmailSender{
		sendFn: func(_ context.Context, to, _ string) error {
			assert.Equal(t, userEmail, to)
			emailSent = true
			return nil
		},
	}

	engine := setupAuthControllerWithVerificationSvc(t, claims, credRepo, emailSender)

	body := `{"type":"email","identifier":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, emailSent, "email sender should have been called")
}

// ──────────────────────────────────────────────
// ConfirmVerification tests
// ──────────────────────────────────────────────

func TestConfirmVerification_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConfirmVerification_InvalidType(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"sms","identifier":"1234567890","code":"000"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "type must be")
}

func TestConfirmVerification_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"email","identifier":"user@example.com","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConfirmVerification_CodeVerifyFails(t *testing.T) {
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	credRepo := &mockCredentialRepoForController{}
	emailSender := &mockEmailSender{}
	engine := setupAuthControllerWithVerificationSvc(t, claims, credRepo, emailSender)

	// miniredis does not support cjson Lua scripts, so VerifyCode will fail
	body := `{"type":"email","identifier":"user@example.com","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid verification code")
}
