package domain

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestAccessTokenClaims_EffectivePrincipalType(t *testing.T) {
	var nilClaims *AccessTokenClaims
	assert.Empty(t, nilClaims.EffectivePrincipalType())

	tests := []struct {
		name   string
		claims AccessTokenClaims
		want   PrincipalType
	}{
		{name: "explicit user session wins", claims: AccessTokenClaims{PrincipalType: PrincipalTypeUserSession, AccountID: "account", ClientID: "client"}, want: PrincipalTypeUserSession},
		{name: "legacy delegated user", claims: AccessTokenClaims{AccountID: "account", ClientID: "client"}, want: PrincipalTypeDelegatedUser},
		{name: "legacy user session", claims: AccessTokenClaims{AccountID: "account"}, want: PrincipalTypeUserSession},
		{name: "legacy client", claims: AccessTokenClaims{ClientID: "client"}, want: PrincipalTypeClient},
		{name: "empty claims", claims: AccessTokenClaims{}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.claims.EffectivePrincipalType())
		})
	}
}

func TestAccessTokenClaims_PrincipalPredicates(t *testing.T) {
	var nilClaims *AccessTokenClaims
	assert.False(t, nilClaims.IsUserSessionPrincipal())
	assert.False(t, nilClaims.IsDelegatedUserPrincipal())
	assert.False(t, nilClaims.IsClientPrincipal())

	user := &AccessTokenClaims{AccountID: "account", SessionID: "session", PrincipalType: PrincipalTypeUserSession}
	assert.True(t, user.IsUserSessionPrincipal())
	assert.False(t, user.IsDelegatedUserPrincipal())
	assert.False(t, user.IsClientPrincipal())

	assert.False(t, (&AccessTokenClaims{AccountID: "account", PrincipalType: PrincipalTypeUserSession}).IsUserSessionPrincipal())
	assert.False(t, (&AccessTokenClaims{SessionID: "session", PrincipalType: PrincipalTypeUserSession}).IsUserSessionPrincipal())

	delegated := &AccessTokenClaims{AccountID: "account", ClientID: "client", PrincipalType: PrincipalTypeDelegatedUser}
	assert.True(t, delegated.IsDelegatedUserPrincipal())
	assert.False(t, delegated.IsUserSessionPrincipal())
	assert.False(t, delegated.IsClientPrincipal())
	assert.False(t, (&AccessTokenClaims{AccountID: "account", PrincipalType: PrincipalTypeDelegatedUser}).IsDelegatedUserPrincipal())
	assert.False(t, (&AccessTokenClaims{ClientID: "client", PrincipalType: PrincipalTypeDelegatedUser}).IsDelegatedUserPrincipal())

	client := &AccessTokenClaims{ClientID: "client", PrincipalType: PrincipalTypeClient}
	assert.True(t, client.IsClientPrincipal())
	assert.False(t, client.IsUserSessionPrincipal())
	assert.False(t, client.IsDelegatedUserPrincipal())
	assert.False(t, (&AccessTokenClaims{ClientID: "client", AccountID: "account", PrincipalType: PrincipalTypeClient}).IsClientPrincipal())
	assert.False(t, (&AccessTokenClaims{ClientID: "client", SessionID: "session", PrincipalType: PrincipalTypeClient}).IsClientPrincipal())
	assert.False(t, (&AccessTokenClaims{PrincipalType: PrincipalTypeClient}).IsClientPrincipal())
}

func TestAccessTokenClaims_HasAudience(t *testing.T) {
	var nilClaims *AccessTokenClaims
	assert.False(t, nilClaims.HasAudience(GossoAPIResourceAudience))

	claims := &AccessTokenClaims{RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{
		"https://api.example.test",
		GossoAPIResourceAudience,
	}}}
	assert.False(t, claims.HasAudience(""))
	assert.True(t, claims.HasAudience(GossoAPIResourceAudience))
	assert.True(t, claims.HasAudience("https://api.example.test"))
	assert.False(t, claims.HasAudience("https://other.example.test"))
}
