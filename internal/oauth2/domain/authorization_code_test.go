package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ──────────────────────────────────────────────
// VerifyPKCE
// ──────────────────────────────────────────────

func TestVerifyPKCE_NoChallenge(t *testing.T) {
	code := &AuthorizationCode{
		CodeChallenge:       "",
		CodeChallengeMethod: "",
	}
	assert.True(t, code.VerifyPKCE("any-verifier"))
}

func TestVerifyPKCE_S256_Valid(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := HashPKCEVerifier(verifier)

	code := &AuthorizationCode{
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
	assert.True(t, code.VerifyPKCE(verifier))
}

func TestVerifyPKCE_S256_Invalid(t *testing.T) {
	code := &AuthorizationCode{
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}
	assert.False(t, code.VerifyPKCE("wrong-verifier"))
}

func TestVerifyPKCE_UnsupportedMethod(t *testing.T) {
	code := &AuthorizationCode{
		CodeChallenge:       "some-challenge",
		CodeChallengeMethod: "plain",
	}
	assert.False(t, code.VerifyPKCE("some-challenge"))
}

// ──────────────────────────────────────────────
// HashPKCEVerifier
// ──────────────────────────────────────────────

func TestHashPKCEVerifier_Deterministic(t *testing.T) {
	verifier := "test-verifier-123"
	h1 := HashPKCEVerifier(verifier)
	h2 := HashPKCEVerifier(verifier)
	assert.Equal(t, h1, h2)
	assert.NotEmpty(t, h1)
}

func TestHashPKCEVerifier_DifferentInputs(t *testing.T) {
	assert.NotEqual(t, HashPKCEVerifier("a"), HashPKCEVerifier("b"))
}

// ──────────────────────────────────────────────
// IsExpired
// ──────────────────────────────────────────────

func TestAuthorizationCode_IsExpired_Past(t *testing.T) {
	code := &AuthorizationCode{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	assert.True(t, code.IsExpired())
}

func TestAuthorizationCode_IsExpired_Future(t *testing.T) {
	code := &AuthorizationCode{ExpiresAt: time.Now().Add(1 * time.Hour)}
	assert.False(t, code.IsExpired())
}
