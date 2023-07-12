package authorization

import (
	"testing"

	"github.com/rushairer/gosso/core/helper"
	"github.com/stretchr/testify/assert"
)

func TestSaveUserNil(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())

	var user *User
	err := userRepository.SaveUser(user)
	assert.Equal(t, err, ErrInvalidUser)
}

func TestSaveUserWithoutName(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())

	user := &User{}
	err := userRepository.SaveUser(user)
	assert.Equal(t, err, ErrInvalidUserName)
}

func TestSaveUser(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())

	user := &User{
		Name: "test_username",
	}

	defer userRepository.DeleteUser(user, false)

	err := userRepository.SaveUser(user)
	assert.Nil(t, err)
}

func TestFindUserByName(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())

	user := &User{
		Name: "test_username",
	}

	defer userRepository.DeleteUser(user, false)

	err := userRepository.SaveUser(user)
	assert.Nil(t, err)

	user, err = userRepository.FindUserByName(user.Name)
	assert.Nil(t, err)
	assert.False(t, user.IsDeleted())
}

func TestDeleteUser(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())

	user := &User{
		Name: "test_username",
	}

	err := userRepository.SaveUser(user)
	assert.Nil(t, err)

	user, err = userRepository.FindUserByName(user.Name)
	assert.Nil(t, err)
	assert.False(t, user.IsDeleted())

	err = userRepository.DeleteUser(user, true)
	assert.Nil(t, err)

	user, err = userRepository.FindUserByName(user.Name)
	assert.Nil(t, err)
	assert.True(t, user.IsDeleted())

	err = userRepository.DeleteUser(user, false)
	assert.Nil(t, err)
}
