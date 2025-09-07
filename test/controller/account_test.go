package controller_test

import (
	"context"
	"gosso/utility"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAccountController_EmailRegister(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	engine := utility.NewTestEngine(ctx, true)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/email", strings.NewReader(`{"address": "test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	<-ctx.Done()
}

func TestAccountController_PhoneRegister(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	engine := utility.NewTestEngine(ctx, true)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/phone", strings.NewReader(`{"number": "12345678901"}`))
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	<-ctx.Done()
}
