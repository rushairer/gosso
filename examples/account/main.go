package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/rushairer/gosso/internal/account"
	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/db"
)

// 账号模块使用示例
func main() {
	// 1. 连接数据库
	dbConfig := &db.Config{
		Host:            "localhost",
		Port:            5432,
		User:            "postgres",
		Password:        "password",
		Database:        "gosso",
		SSLMode:         "disable",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 10 * time.Minute,
	}

	database, err := db.Connect(dbConfig)
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	defer database.Close()

	// 2. 初始化账号服务
	accountService := account.InitializeAccountModule(database.DB, nil)

	ctx := context.Background()

	// 3. 注册账号示例
	registerExample(ctx, accountService)

	// 4. 查找账号示例
	findAccountExample(ctx, accountService)

	// 5. 修改密码示例
	changePasswordExample(ctx, accountService)

	// 6. 绑定第三方身份示例
	bindFederatedIdentityExample(ctx, accountService)

	// 7. 分配角色示例
	assignRoleExample(ctx, accountService)

	// 8. 软删除账号示例
	softDeleteAccountExample(ctx, accountService)
}

// registerExample 注册账号示例
func registerExample(ctx context.Context, accountService service.AccountService) {
	req := &service.RegisterAccountRequest{
		Username:    "johndoe",
		DisplayName: "John Doe",
		Email:       "john.doe@example.com",
		Password:    "SecurePassword123!",
		Locale:      "en",
		Timezone:    "America/New_York",
		Metadata: map[string]any{
			"source":      "web",
			"campaign_id": "summer2024",
		},
	}

	account, err := accountService.RegisterAccount(ctx, req)
	if err != nil {
		log.Printf("注册失败: %v", err)
		return
	}

	fmt.Printf("✅ 注册成功:\n")
	fmt.Printf("   账号 ID: %s\n", account.ID)
	fmt.Printf("   用户名: %v\n", account.Username)
	fmt.Printf("   显示名称: %s\n", account.DisplayName)
	fmt.Printf("   状态: %s\n", account.Status)
}

// findAccountExample 查找账号示例
func findAccountExample(ctx context.Context, accountService service.AccountService) {
	// 根据用户名查找
	account, err := accountService.FindAccountByUsername(ctx, "johndoe")
	if err != nil {
		log.Printf("查找账号失败: %v", err)
		return
	}

	fmt.Printf("✅ 查找账号成功:\n")
	fmt.Printf("   账号 ID: %s\n", account.ID)
	fmt.Printf("   用户名: %v\n", account.Username)
	fmt.Printf("   创建时间: %s\n", account.CreatedAt.Format(time.RFC3339))
}

// changePasswordExample 修改密码示例
func changePasswordExample(ctx context.Context, accountService service.AccountService) {
	// 假设已经获取了账号 ID
	accountID := "some-account-id"
	oldPassword := "OldPassword123!"
	newPassword := "NewSecurePassword456!"

	err := accountService.ChangePassword(ctx, accountID, oldPassword, newPassword)
	if err != nil {
		log.Printf("修改密码失败: %v", err)
		return
	}

	fmt.Printf("✅ 密码修改成功\n")
}

// bindFederatedIdentityExample 绑定第三方身份示例
func bindFederatedIdentityExample(ctx context.Context, accountService service.AccountService) {
	accountID := "some-account-id"
	provider := domain.ProviderGoogle
	providerUserID := "google-user-12345"
	profile := map[string]any{
		"email":    "john.doe@gmail.com",
		"name":     "John Doe",
		"picture":  "https://lh3.googleusercontent.com/...",
		"verified": true,
		"locale":   "en",
	}

	err := accountService.BindFederatedIdentity(ctx, accountID, provider, providerUserID, profile)
	if err != nil {
		log.Printf("绑定第三方身份失败: %v", err)
		return
	}

	fmt.Printf("✅ 成功绑定 Google 账号\n")
}

// assignRoleExample 分配角色示例
func assignRoleExample(ctx context.Context, accountService service.AccountService) {
	accountID := "some-account-id"
	roleID := "admin-role-id"

	err := accountService.AssignRole(ctx, accountID, roleID)
	if err != nil {
		log.Printf("分配角色失败: %v", err)
		return
	}

	fmt.Printf("✅ 成功分配角色\n")
}

// softDeleteAccountExample 软删除账号示例
func softDeleteAccountExample(ctx context.Context, accountService service.AccountService) {
	accountID := "some-account-id"

	err := accountService.SoftDeleteAccount(ctx, accountID)
	if err != nil {
		log.Printf("删除账号失败: %v", err)
		return
	}

	fmt.Printf("✅ 账号已软删除（保留数据用于审计）\n")
}
