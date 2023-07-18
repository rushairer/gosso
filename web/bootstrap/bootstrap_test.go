package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
	"gotest.tools/assert"
)

func TestSetupRouter(t *testing.T) {
	server := gin.Default()

	SetupServer(server)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test/alive", nil)
	server.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "pong", w.Body.String())
}

func TestSocialiteMiddleware(t *testing.T) {
	server := gin.Default()

	SetupServer(server)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/socials/github_1", nil)
	server.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	name, err := gothic.GetProviderName(req)
	assert.NilError(t, err)
	assert.Equal(t, name, "github_1")
}

func TestSocialsSignIn(t *testing.T) {
	server := gin.Default()

	SetupServer(server)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/socials/github_1", nil)
	server.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
}
