package authorization

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/rushairer/gosso/core/helper"
	"github.com/stretchr/testify/assert"
)

func TestCreateUser(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	user := User{
		Name: "test_username",
	}
	userRepository.DeleteUser(ctx, user)

	savedUser, err := userRepository.CreateUser(ctx, user)

	assert.NoError(t, err)
	assert.NotEmpty(t, savedUser.Id)
	assert.Equal(t, savedUser.CreatedAt, savedUser.UpdatedAt)
	assert.Equal(t, savedUser.Name, user.Name)

	userRepository.DeleteUser(ctx, savedUser)
}

func TestGetUser(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	user := User{
		Name: "test_username",
	}
	userRepository.DeleteUser(ctx, user)

	savedUser, err := userRepository.CreateUser(ctx, user)

	assert.NoError(t, err)

	getUser, err := userRepository.GetUser(ctx, savedUser.Name)
	assert.NoError(t, err)
	assert.Equal(t, savedUser.Id, getUser.Id)
	assert.Equal(t, savedUser.Name, getUser.Name)
	assert.Equal(t, savedUser.CreatedAt, getUser.CreatedAt)

	userRepository.DeleteUser(ctx, savedUser)
}

func TestDeleteUser(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	user := User{
		Name: "test_username",
	}

	userRepository.DeleteUser(ctx, user)

	savedUser, err := userRepository.CreateUser(ctx, user)
	assert.NoError(t, err)

	err = userRepository.DeleteUser(ctx, savedUser)
	assert.NoError(t, err)
}

func TestSoftDeleteUser(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	user := User{
		Name: "test_username",
	}
	userRepository.DeleteUser(ctx, user)

	savedUser, err := userRepository.CreateUser(ctx, user)
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)
	err = userRepository.SoftDeleteUser(ctx, savedUser)
	assert.NoError(t, err)

	getUser, err := userRepository.GetUser(ctx, savedUser.Name)
	assert.NoError(t, err)
	assert.NotNil(t, getUser.DeletedAt)
	assert.NotEqual(t, savedUser.UpdatedAt, getUser.UpdatedAt)

	userRepository.DeleteUser(ctx, savedUser)

}

func TestCreateAccountWithConnectedAccount(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	connectedAccount, err := NewConnectedAccountFromGothUser(goth.User{
		Provider: "github_1",
		Email:    "tester@apigg.net",
		Name:     "tester",
		NickName: "nickname",
		UserID:   "10000",
	})
	if assert.NoError(t, err) {
		userId, err := userRepository.CreateAccountWithConnectedAccount(
			ctx,
			connectedAccount,
		)

		assert.NoError(t, err)
		assert.NotNil(t, userId)

		userWithDetail, err := userRepository.GetUserWithDetailById(ctx, userId)
		assert.NoError(t, err)
		assert.NotNil(t, userWithDetail.UserDetail)

		err = userRepository.DeleteAccount(ctx, userId)
		assert.NoError(t, err)
	}
}

func TestGetConnectedAccount(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	userRepository := NewUserRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	getConnectedAccount, err := userRepository.GetConnectedAccount(ctx, "provider", "user_id")
	assert.Error(t, err)
	assert.EqualError(t, err, sql.ErrNoRows.Error())
	assert.Equal(t, err, sql.ErrNoRows)
	assert.True(t, len(getConnectedAccount.UserId) == 0)
}
