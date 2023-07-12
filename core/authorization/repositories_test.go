package authorization

import (
	"testing"

	"github.com/rushairer/gosso/core/helper"
	"github.com/stretchr/testify/assert"
)

func TestUserRepository(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())

	user := &User{}
	err := userRepository.SaveUser(user)
	assert.Equal(t, err, ErrInvalidUserName)

	userName := "test_username"

	user.Name = userName
	err = userRepository.SaveUser(user)
	assert.Nil(t, err)

	defer func() {
		if err := recover(); err != nil {
			userRepository.DeleteUser(user, false)
		}
	}()

	user, err = userRepository.FindUserByName(userName)
	assert.Nil(t, err)
	assert.False(t, user.IsDeleted())

	err = userRepository.DeleteUser(user, true)
	assert.Nil(t, err)

	user, err = userRepository.FindUserByName(userName)
	assert.Nil(t, err)
	assert.True(t, user.IsDeleted())

	err = userRepository.DeleteUser(user, false)
	assert.Nil(t, err)
}
