package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepository "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	gm "github.com/rushairer/gosso/middleware"
)

// ──────────────────────────────────────────────
// Mock AccountService
// ──────────────────────────────────────────────

type mockAccountService struct {
	findByIDFn     func() (*accountDomain.Account, error)
	listAccountsFn func() ([]*accountDomain.Account, int, error)
	deleteFn       func() error
	suspendFn      func() error
	activateFn     func() error
	getRolesFn     func() ([]*accountDomain.Role, error)
	assignRoleFn   func() error
	removeRoleFn   func() error
}

func (m *mockAccountService) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountService) FindAccountByID(_ context.Context, _ string) (*accountDomain.Account, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn()
	}
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountService) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountService) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return nil
}
func (m *mockAccountService) SoftDeleteAccount(_ context.Context, _ string) error {
	if m.deleteFn != nil {
		return m.deleteFn()
	}
	return nil
}
func (m *mockAccountService) VerifyCredential(_ context.Context, _ string) error     { return nil }
func (m *mockAccountService) ChangePassword(_ context.Context, _, _, _ string) error { return nil }
func (m *mockAccountService) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockAccountService) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	return nil
}
func (m *mockAccountService) AssignRole(_ context.Context, _, _ string) error {
	if m.assignRoleFn != nil {
		return m.assignRoleFn()
	}
	return nil
}
func (m *mockAccountService) RemoveRole(_ context.Context, _, _ string) error {
	if m.removeRoleFn != nil {
		return m.removeRoleFn()
	}
	return nil
}
func (m *mockAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	if m.listAccountsFn != nil {
		return m.listAccountsFn()
	}
	return nil, 0, nil
}
func (m *mockAccountService) SuspendAccount(_ context.Context, _ string) error {
	if m.suspendFn != nil {
		return m.suspendFn()
	}
	return nil
}
func (m *mockAccountService) ActivateAccount(_ context.Context, _ string) error {
	if m.activateFn != nil {
		return m.activateFn()
	}
	return nil
}
func (m *mockAccountService) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	if m.getRolesFn != nil {
		return m.getRolesFn()
	}
	return nil, nil
}

// ──────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────

const validUUID = "550e8400-e29b-41d4-a716-446655440000"

func setupAdminController(accountSvc *mockAccountService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := NewAdminController(accountSvc, zap.NewNop())

	api := engine.Group("/api")
	ctrl.RegisterRoutes(api.Group("/admin"))

	return engine
}

// setupAdminControllerWithAdminID sets ContextKeyAccountID in the gin context
// so that isSelfAccount checks can be exercised.
func setupAdminControllerWithAdminID(accountSvc *mockAccountService, adminID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(ctx *gin.Context) {
		ctx.Set(gm.ContextKeyAccountID, adminID)
		ctx.Next()
	})

	ctrl := NewAdminController(accountSvc, zap.NewNop())

	api := engine.Group("/api")
	ctrl.RegisterRoutes(api.Group("/admin"))

	return engine
}

func newAdminTestAccount() *accountDomain.Account {
	return &accountDomain.Account{
		ID:          validUUID,
		DisplayName: "Admin Test User",
		Status:      accountDomain.AccountStatusActive,
		Locale:      "en",
	}
}

// ──────────────────────────────────────────────
// ListAccounts Tests
// ──────────────────────────────────────────────

func TestListAccounts_Success(t *testing.T) {
	accounts := []*accountDomain.Account{newAdminTestAccount()}
	accountSvc := &mockAccountService{
		listAccountsFn: func() ([]*accountDomain.Account, int, error) {
			return accounts, 1, nil
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, float64(1), data["total"])
}

func TestListAccounts_Pagination(t *testing.T) {
	accountSvc := &mockAccountService{
		listAccountsFn: func() ([]*accountDomain.Account, int, error) {
			return nil, 0, nil
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts?page=2&page_size=50", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListAccounts_Error(t *testing.T) {
	accountSvc := &mockAccountService{
		listAccountsFn: func() ([]*accountDomain.Account, int, error) {
			return nil, 0, fmt.Errorf("db error")
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAccounts_LargePageSizeClamped(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts?page_size=500", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAddRole_InvalidAccountUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	body := fmt.Sprintf(`{"role_id":%q}`, validUUID)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/not-a-uuid/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddRole_Error(t *testing.T) {
	accountSvc := &mockAccountService{
		assignRoleFn: func() error { return fmt.Errorf("role assignment failed") },
	}
	engine := setupAdminController(accountSvc)

	roleUUID := "660e8400-e29b-41d4-a716-446655440001"
	body := fmt.Sprintf(`{"role_id":%q}`, roleUUID)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRemoveRole_InvalidAccountUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	roleUUID := "660e8400-e29b-41d4-a716-446655440001"
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/not-a-uuid/roles/"+roleUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// GetAccount Tests
// ──────────────────────────────────────────────

func TestGetAccount_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return newAdminTestAccount(), nil
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/"+validUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAccount_NotFound(t *testing.T) {
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return nil, accountRepository.ErrAccountNotFound
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/"+validUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetAccount_InvalidUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/not-a-uuid", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// DeleteAccount Tests
// ──────────────────────────────────────────────

func TestDeleteAccount_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		deleteFn: func() error { return nil },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/"+validUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteAccount_Error(t *testing.T) {
	accountSvc := &mockAccountService{
		deleteFn: func() error { return fmt.Errorf("cannot delete") },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/"+validUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ──────────────────────────────────────────────
// Disable/Enable Account Tests
// ──────────────────────────────────────────────

func TestDisableAccount_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		suspendFn: func() error { return nil },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/disable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEnableAccount_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		activateFn: func() error { return nil },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/enable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDisableAccount_Error(t *testing.T) {
	accountSvc := &mockAccountService{
		suspendFn: func() error { return fmt.Errorf("already suspended") },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/disable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ──────────────────────────────────────────────
// Roles Tests
// ──────────────────────────────────────────────

func TestGetAccountRoles_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		getRolesFn: func() ([]*accountDomain.Role, error) {
			return []*accountDomain.Role{{ID: "role-1", Name: "admin"}}, nil
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/"+validUUID+"/roles", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAddRole_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		assignRoleFn: func() error { return nil },
	}
	engine := setupAdminController(accountSvc)

	body := fmt.Sprintf(`{"role_id":%q}`, validUUID)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAddRole_InvalidBody(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/roles", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddRole_InvalidRoleUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	body := `{"role_id":"not-a-uuid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveRole_Success(t *testing.T) {
	accountSvc := &mockAccountService{
		removeRoleFn: func() error { return nil },
	}
	engine := setupAdminController(accountSvc)

	roleUUID := "660e8400-e29b-41d4-a716-446655440001"
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/"+validUUID+"/roles/"+roleUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRemoveRole_InvalidRoleUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/"+validUUID+"/roles/not-a-uuid", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// Error-path tests for missing coverage
// ──────────────────────────────────────────────

func TestListAccounts_InvalidStatus(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts?status=bogus", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccount_GenericError(t *testing.T) {
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return nil, fmt.Errorf("unexpected db failure")
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/"+validUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteAccount_InvalidUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/not-a-uuid", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteAccount_SelfAccount(t *testing.T) {
	engine := setupAdminControllerWithAdminID(&mockAccountService{}, validUUID)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/"+validUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDisableAccount_InvalidUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/not-a-uuid/disable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDisableAccount_SelfAccount(t *testing.T) {
	engine := setupAdminControllerWithAdminID(&mockAccountService{}, validUUID)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/disable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDisableAccount_NotFound(t *testing.T) {
	accountSvc := &mockAccountService{
		suspendFn: func() error { return accountRepository.ErrAccountNotFound },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/disable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDisableAccount_InvalidTransition(t *testing.T) {
	accountSvc := &mockAccountService{
		suspendFn: func() error { return accountRepository.ErrInvalidStatusTransition },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/disable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestEnableAccount_InvalidUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/not-a-uuid/enable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEnableAccount_SelfAccount(t *testing.T) {
	engine := setupAdminControllerWithAdminID(&mockAccountService{}, validUUID)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/enable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestEnableAccount_NotFound(t *testing.T) {
	accountSvc := &mockAccountService{
		activateFn: func() error { return accountRepository.ErrAccountNotFound },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/enable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEnableAccount_InvalidTransition(t *testing.T) {
	accountSvc := &mockAccountService{
		activateFn: func() error { return accountRepository.ErrInvalidStatusTransition },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/enable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestEnableAccount_GenericError(t *testing.T) {
	accountSvc := &mockAccountService{
		activateFn: func() error { return fmt.Errorf("redis connection lost") },
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/accounts/"+validUUID+"/enable", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetAccountRoles_InvalidUUID(t *testing.T) {
	engine := setupAdminController(&mockAccountService{})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/not-a-uuid/roles", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccountRoles_Error(t *testing.T) {
	accountSvc := &mockAccountService{
		getRolesFn: func() ([]*accountDomain.Role, error) {
			return nil, fmt.Errorf("db query failed")
		},
	}
	engine := setupAdminController(accountSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/accounts/"+validUUID+"/roles", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRemoveRole_Error(t *testing.T) {
	accountSvc := &mockAccountService{
		removeRoleFn: func() error { return fmt.Errorf("db delete failed") },
	}
	engine := setupAdminController(accountSvc)

	roleUUID := "660e8400-e29b-41d4-a716-446655440001"
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/accounts/"+validUUID+"/roles/"+roleUUID, nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
