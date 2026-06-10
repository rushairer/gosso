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

// --- HandleServiceError tests ---

func TestHandleServiceError_SentinelMatch(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("not found")
	errMap := map[error]ErrorMapping{
		sentinel: {Status: http.StatusNotFound, Message: "resource not found"},
	}

	HandleServiceError(ctx, logger, sentinel, errMap, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusNotFound, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusNotFound), body["code"])
	assert.Equal(t, "resource not found", body["message"])
}

func TestHandleServiceError_NoMatch(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("not found")
	errMap := map[error]ErrorMapping{
		sentinel: {Status: http.StatusNotFound, Message: "resource not found"},
	}

	unknownErr := errors.New("something unexpected")
	HandleServiceError(ctx, logger, unknownErr, errMap, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusInternalServerError), body["code"])
	assert.Equal(t, "internal error", body["message"])
}

func TestHandleServiceError_EmptyErrorMap(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	errMap := map[error]ErrorMapping{}

	err := errors.New("any error")
	HandleServiceError(ctx, logger, err, errMap, http.StatusConflict, "conflict fallback")

	assert.Equal(t, http.StatusConflict, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusConflict), body["code"])
	assert.Equal(t, "conflict fallback", body["message"])
}

func TestHandleServiceError_NilError(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("not found")
	errMap := map[error]ErrorMapping{
		sentinel: {Status: http.StatusNotFound, Message: "resource not found"},
	}

	assert.NotPanics(t, func() {
		HandleServiceError(ctx, logger, nil, errMap, http.StatusInternalServerError, "internal error")
	})

	// nil should not match any sentinel, so fallback is used
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusInternalServerError), body["code"])
	assert.Equal(t, "internal error", body["message"])
}

func TestHandleServiceError_WrappedErrorMatches(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("forbidden")
	errMap := map[error]ErrorMapping{
		sentinel: {Status: http.StatusForbidden, Message: "access denied"},
	}

	wrappedErr := fmt.Errorf("operation failed: %w", sentinel)
	HandleServiceError(ctx, logger, wrappedErr, errMap, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusForbidden, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, float64(http.StatusForbidden), body["code"])
	assert.Equal(t, "access denied", body["message"])
}

func TestHandleServiceError_WrappedErrorNoMatch(t *testing.T) {
	ctx, recorder := setupTestContext()
	logger := nopLogger()

	sentinel := errors.New("forbidden")
	errMap := map[error]ErrorMapping{
		sentinel: {Status: http.StatusForbidden, Message: "access denied"},
	}

	wrappedErr := fmt.Errorf("wrap: %w", errors.New("something else"))
	HandleServiceError(ctx, logger, wrappedErr, errMap, http.StatusInternalServerError, "internal error")

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
}

// --- HandleClientAuthError tests ---

func TestHandleClientAuthError_SecretRequired(t *testing.T) {
	ctx, recorder := setupTestContext()

	secretRequired := errors.New("client secret required")
	err := secretRequired

	HandleClientAuthError(ctx, err, secretRequired, "client secret is required", "invalid client credentials")

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "client secret is required", body["error_description"])
}

func TestHandleClientAuthError_InvalidClient(t *testing.T) {
	ctx, recorder := setupTestContext()

	secretRequired := errors.New("client secret required")
	err := errors.New("bad credentials")

	HandleClientAuthError(ctx, err, secretRequired, "client secret is required", "invalid client credentials")

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "invalid client credentials", body["error_description"])
}

func TestHandleClientAuthError_WrappedSecretRequired(t *testing.T) {
	ctx, recorder := setupTestContext()

	secretRequired := errors.New("client secret required")
	err := fmt.Errorf("auth failed: %w", secretRequired)

	HandleClientAuthError(ctx, err, secretRequired, "secret required", "bad creds")

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "secret required", body["error_description"])
}
