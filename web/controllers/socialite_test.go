package controllers

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/rushairer/gosso/core/utilities"
	"github.com/stretchr/testify/assert"
)

func TestEmptyGothUser(t *testing.T) {
	user := goth.User{}
	assert.Empty(t, user)
	assert.True(t, utilities.IsEmpty(user))

	user.Name = "name"
	assert.NotEmpty(t, user)
	assert.False(t, utilities.IsEmpty(user))
}
