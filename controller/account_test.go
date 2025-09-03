package controller_test

import (
	"gosso/utility"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountController_EmailRegister(t *testing.T) {
	engine := utility.NewTestEngine()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/email", strings.NewReader(`{"email": "test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAccountController_PhoneRegister(t *testing.T) {
	engine := utility.NewTestEngine()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/phone", strings.NewReader(`{"phone": "12345678901"}`))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
