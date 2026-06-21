package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// MFA Enroll tests
// ──────────────────────────────────────────────

func TestMFAEnroll_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAEnroll_Success(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: nil,
		},
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// EnrollTOTP uses a single transaction for delete + create
	mock.ExpectBegin()
	mock.ExpectCommit()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.NotEmpty(t, data["secret"])
	assert.NotEmpty(t, data["otpauth_url"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAEnroll_ServiceError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: nil,
		},
		createCredentialsErr: fmt.Errorf("db error"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// EnrollTOTP uses a single transaction; CreateCredentials fails -> Rollback
	mock.ExpectBegin()
	mock.ExpectRollback()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// MFA Activate tests
// ──────────────────────────────────────────────

func TestMFAActivate_BadBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAActivate_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAActivate_FindByAccountAndTypeError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeErr: fmt.Errorf("database error"),
	}
	mfaSvc, _ := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAActivate_InvalidCode(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	storedSecret := encryptControllerTestTOTPSecret(t, key.Secret())

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
	}
	mfaSvc, _ := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"code":"000000"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAActivate_NoPendingEnrollment(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptControllerTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
		verifyFirstUnverifiedTOTPOK: false,
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	mock.ExpectBegin()
	mock.ExpectCommit()

	reqBody := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAActivate_Success(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptControllerTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
		verifyFirstUnverifiedTOTPOK: true,
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	mock.ExpectBegin()
	mock.ExpectCommit()

	reqBody := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAActivate_VerifyFirstError(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptControllerTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
		verifyFirstUnverifiedTOTPError: fmt.Errorf("transaction failed"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	mock.ExpectBegin()
	mock.ExpectRollback()

	reqBody := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// MFA Disable tests
// ──────────────────────────────────────────────

func TestMFADisable_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/mfa", strings.NewReader(`{"current_password":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFADisable_Success(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "cred-totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// DisableTOTP: Begin/Commit (single tx)
	mock.ExpectBegin()
	mock.ExpectCommit()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/mfa", strings.NewReader(`{"current_password":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFADisable_ServiceError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "cred-totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
		softDeleteCredentialErr: fmt.Errorf("delete failed"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// DisableTOTP: Begin/SoftDelete fails/Rollback
	mock.ExpectBegin()
	mock.ExpectRollback()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/mfa", strings.NewReader(`{"current_password":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// MFA Generate Backup Codes tests
// ──────────────────────────────────────────────

func TestMFAGenerateBackupCodes_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/backup-codes", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAGenerateBackupCodes_Success(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeBackupCode: nil,
		},
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// GenerateBackupCodes: Begin/Commit (single tx)
	mock.ExpectBegin()
	mock.ExpectCommit()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/backup-codes", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	codes := data["backup_codes"].([]any)
	assert.Len(t, codes, 10)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAGenerateBackupCodes_ServiceError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeBackupCode: nil,
		},
		createCredentialsErr: fmt.Errorf("db error"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// GenerateBackupCodes: Begin/CreateCredentials fails/Rollback
	mock.ExpectBegin()
	mock.ExpectRollback()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/backup-codes", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
