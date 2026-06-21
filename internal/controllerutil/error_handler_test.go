package controllerutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	return ctx, recorder
}

func nopLogger() *zap.Logger {
	return zap.NewNop()
}

// --- AbortWithServiceError tests ---

func TestAbortWithServiceError_SentinelMatch(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("not found")
	rules := []ErrorRule{
		{Sentinel: sentinel, Mapping: ErrorMapping{Status: http.StatusNotFound, Message: "resource not found"}},
	}

	AbortWithServiceError(ctx, logger, sentinel, rules, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusNotFound, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusNotFound), body["code"])
	assert.Equal(t, "resource not found", body["message"])
}

func TestAbortWithServiceError_NoMatch(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("not found")
	rules := []ErrorRule{
		{Sentinel: sentinel, Mapping: ErrorMapping{Status: http.StatusNotFound, Message: "resource not found"}},
	}

	unknownErr := errors.New("something unexpected")
	AbortWithServiceError(ctx, logger, unknownErr, rules, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusInternalServerError), body["code"])
	assert.Equal(t, "internal error", body["message"])
}

func TestAbortWithServiceError_EmptyErrorMap(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	rules := []ErrorRule{}

	err := errors.New("any error")
	AbortWithServiceError(ctx, logger, err, rules, http.StatusConflict, "conflict fallback")

	assert.Equal(t, http.StatusConflict, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusConflict), body["code"])
	assert.Equal(t, "conflict fallback", body["message"])
}

func TestAbortWithServiceError_NilError(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("not found")
	rules := []ErrorRule{
		{Sentinel: sentinel, Mapping: ErrorMapping{Status: http.StatusNotFound, Message: "resource not found"}},
	}

	assert.NotPanics(t, func() {
		AbortWithServiceError(ctx, logger, nil, rules, http.StatusInternalServerError, "internal error")
	})

	// nil should not match any sentinel, so fallback is used
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusInternalServerError), body["code"])
	assert.Equal(t, "internal error", body["message"])
}

func TestAbortWithServiceError_WrappedErrorMatches(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("forbidden")
	rules := []ErrorRule{
		{Sentinel: sentinel, Mapping: ErrorMapping{Status: http.StatusForbidden, Message: "access denied"}},
	}

	wrappedErr := fmt.Errorf("operation failed: %w", sentinel)
	AbortWithServiceError(ctx, logger, wrappedErr, rules, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusForbidden, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusForbidden), body["code"])
	assert.Equal(t, "access denied", body["message"])
}

func TestAbortWithServiceError_WrappedErrorNoMatch(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("forbidden")
	rules := []ErrorRule{
		{Sentinel: sentinel, Mapping: ErrorMapping{Status: http.StatusForbidden, Message: "access denied"}},
	}

	wrappedErr := fmt.Errorf("wrap: %w", errors.New("something else"))
	AbortWithServiceError(ctx, logger, wrappedErr, rules, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
}

// --- HandleClientAuthError tests ---

func TestHandleClientAuthError_SecretRequired(t *testing.T) {
	ctx, recorder := setupTestContext()

	secretRequired := errors.New("client secret required")
	err := secretRequired

	HandleClientAuthError(ctx, zap.NewNop(), err)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "client authentication failed", body["error_description"])
}

func TestHandleClientAuthError_InvalidClient(t *testing.T) {
	ctx, recorder := setupTestContext()

	err := errors.New("bad credentials")

	HandleClientAuthError(ctx, zap.NewNop(), err)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "client authentication failed", body["error_description"])
}

func TestHandleClientAuthError_WrappedSecretRequired(t *testing.T) {
	ctx, recorder := setupTestContext()

	secretRequired := errors.New("client secret required")
	err := fmt.Errorf("auth failed: %w", secretRequired)

	HandleClientAuthError(ctx, zap.NewNop(), err)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "client authentication failed", body["error_description"])
}
