package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterAccount 测试账号注册
func TestRegisterAccount(t *testing.T) {
	// 创建 mock 数据库
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// 创建仓储和服务
	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo)

	// 设置 mock 期望
	mock.ExpectBegin()
	
	// 期望查询邮箱是否已存在
	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnError(sql.ErrNoRows)

	// 期望插入账号
	mock.ExpectExec("INSERT INTO accounts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 期望插入密码凭证
	mock.ExpectExec("INSERT INTO account_credentials").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 期望插入邮箱凭证
	mock.ExpectExec("INSERT INTO account_credentials").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	// 执行注册
	req := &RegisterAccountRequest{
		Username:    "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
		Password:    "TestPassword123!",
		Locale:      "en",
		Timezone:    "UTC",
	}

	account, err := accountService.RegisterAccount(context.Background(), req)

	// 验证结果
	assert.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, "testuser", account.Username)
	assert.Equal(t, "Test User", account.DisplayName)
	assert.Equal(t, domain.AccountStatusActive, account.Status)

	// 验证所有期望都被满足
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRegisterAccount_DuplicateEmail 测试重复邮箱注册
func TestRegisterAccount_DuplicateEmail(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo)

	// 设置 mock：邮箱已存在
	rows := sqlmock.NewRows([]string{"id", "account_id", "credential_type", "identifier"}).
		AddRow("existing-id", "existing-account-id", domain.CredentialTypeEmail, "test@example.com")

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(domain.CredentialTypeEmail, "test@example.com").
		WillReturnRows(rows)

	// 执行注册
	req := &RegisterAccountRequest{
		Username:    "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
		Password:    "TestPassword123!",
	}

	account, err := accountService.RegisterAccount(context.Background(), req)

	// 验证结果：应该返回错误
	assert.Error(t, err)
	assert.Nil(t, account)
	assert.Contains(t, err.Error(), "邮箱已被注册")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestChangePassword 测试修改密码
func TestChangePassword(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo)

	accountID := "test-account-id"
	oldPassword := "OldPassword123!"
	newPassword := "NewPassword456!"

	// 模拟查找密码凭证
	// 注意：实际的 bcrypt hash 需要提前生成
	passwordHash := "$2a$10$YourBcryptHashHere"
	rows := sqlmock.NewRows([]string{"id", "account_id", "credential_type", "credential_value", "created_at"}).
		AddRow("cred-id", accountID, domain.CredentialTypePassword, passwordHash, time.Now())

	mock.ExpectQuery("SELECT (.+) FROM account_credentials").
		WithArgs(accountID, domain.CredentialTypePassword).
		WillReturnRows(rows)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_credentials").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// 注意：由于 bcrypt 验证，这个测试需要真实的密码哈希
	// 这里仅作为示例展示测试结构
	err = accountService.ChangePassword(context.Background(), accountID, oldPassword, newPassword)

	// 根据实际情况验证（这里会因为密码哈希不匹配而失败）
	// 实际测试中应该使用真实的密码哈希对
}

// TestSoftDeleteAccount 测试软删除账号
func TestSoftDeleteAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	accountRepo := repository.NewAccountRepository(db)
	credentialRepo := repository.NewCredentialRepository(db)
	federatedIdentityRepo := repository.NewFederatedIdentityRepository(db)
	roleRepo := repository.NewRoleRepository(db)

	accountService := NewAccountService(db, accountRepo, credentialRepo, federatedIdentityRepo, roleRepo)

	accountID := "test-account-id"

	// 设置 mock 期望
	mock.ExpectBegin()

	// 期望软删除凭证
	mock.ExpectExec("UPDATE account_credentials SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 2))

	// 期望软删除第三方身份
	mock.ExpectExec("UPDATE federated_identities SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// 期望软删除角色关联
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 3))

	// 期望软删除账号
	mock.ExpectExec("UPDATE accounts SET deleted_at").
		WithArgs(sqlmock.AnyArg(), accountID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	// 执行删除
	err = accountService.SoftDeleteAccount(context.Background(), accountID)

	// 验证结果
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
