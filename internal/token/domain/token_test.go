package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashToken_Deterministic(t *testing.T) {
	token := "test-token-123"
	h1 := HashToken(token)
	h2 := HashToken(token)
	assert.Equal(t, h1, h2)
	assert.NotEmpty(t, h1)
	assert.Len(t, h1, 64) // SHA256 hex = 64 chars
}

func TestHashToken_DifferentInputs(t *testing.T) {
	assert.NotEqual(t, HashToken("a"), HashToken("b"))
}

func TestHashToken_Empty(t *testing.T) {
	h := HashToken("")
	assert.NotEmpty(t, h)
	assert.Len(t, h, 64)
}
