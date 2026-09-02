package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
)

type requestedAuthSessionValidator struct{ session *sessionDomain.Session }

func (v requestedAuthSessionValidator) ValidateSession(context.Context, string) (*sessionDomain.Session, error) {
	return v.session, nil
}

func TestRequireRequestedAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(nil)
	now := time.Now()

	t.Run("AAL2 succeeds with fresh strong authentication", func(t *testing.T) {
		ctrl := &OAuth2Controller{sessionValidator: requestedAuthSessionValidator{session: &sessionDomain.Session{StrongAuthAt: now, AuthMethods: []string{"pwd", "otp"}}}}
		require.NoError(t, ctrl.requireRequestedAuthentication(ctx, "sid", "urn:gouno:aal2", "600"))
	})

	t.Run("password-only session requires reauthentication", func(t *testing.T) {
		ctrl := &OAuth2Controller{sessionValidator: requestedAuthSessionValidator{session: &sessionDomain.Session{AuthenticatedAt: now}}}
		err := ctrl.requireRequestedAuthentication(ctx, "sid", "urn:gouno:aal2", "")
		assert.ErrorIs(t, err, errReauthenticationRequired)
	})

	t.Run("stale strong authentication requires reauthentication", func(t *testing.T) {
		ctrl := &OAuth2Controller{sessionValidator: requestedAuthSessionValidator{session: &sessionDomain.Session{StrongAuthAt: now.Add(-11 * time.Minute)}}}
		err := ctrl.requireRequestedAuthentication(ctx, "sid", "urn:gouno:aal2", "600")
		assert.ErrorIs(t, err, errReauthenticationRequired)
	})

	t.Run("unsupported ACR and malformed max_age are request errors", func(t *testing.T) {
		ctrl := &OAuth2Controller{}
		assert.True(t, errors.Is(ctrl.requireRequestedAuthentication(ctx, "sid", "weak", ""), errUnsupportedACR))
		assert.True(t, errors.Is(ctrl.requireRequestedAuthentication(ctx, "sid", "", "-1"), errInvalidMaxAge))
	})
}
