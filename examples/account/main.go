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

// Account module usage example
func main() {
	// 1. Connect to the database
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
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// 2. Initialize the account service
	accountService := account.InitializeAccountModule(database.DB, nil)

	ctx := context.Background()

	// 3. Register account example
	registerExample(ctx, accountService)

	// 4. Find account example
	findAccountExample(ctx, accountService)

	// 5. Change password example
	changePasswordExample(ctx, accountService)

	// 6. Bind third-party identity example
	bindFederatedIdentityExample(ctx, accountService)

	// 7. Assign role example
	assignRoleExample(ctx, accountService)

	// 8. Soft-delete account example
	softDeleteAccountExample(ctx, accountService)
}

// registerExample registers an account as an example
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
		log.Printf("Registration failed: %v", err)
		return
	}

	fmt.Printf("✅ Registration succeeded:\n")
	fmt.Printf("   Account ID: %s\n", account.ID)
	fmt.Printf("   Username: %v\n", account.Username)
	fmt.Printf("   Display Name: %s\n", account.DisplayName)
	fmt.Printf("   Status: %s\n", account.Status)
}

// findAccountExample lists finding an account as an example
func findAccountExample(ctx context.Context, accountService service.AccountService) {
	// Find by username
	account, err := accountService.FindAccountByUsername(ctx, "johndoe")
	if err != nil {
		log.Printf("Failed to find account: %v", err)
		return
	}

	fmt.Printf("✅ Found account:\n")
	fmt.Printf("   Account ID: %s\n", account.ID)
	fmt.Printf("   Username: %v\n", account.Username)
	fmt.Printf("   Created At: %s\n", account.CreatedAt.Format(time.RFC3339))
}

// changePasswordExample changes password as an example
func changePasswordExample(ctx context.Context, accountService service.AccountService) {
	// Assuming the account ID has been obtained
	accountID := "some-account-id"
	oldPassword := "OldPassword123!"
	newPassword := "NewSecurePassword456!"

	err := accountService.ChangePassword(ctx, accountID, oldPassword, newPassword)
	if err != nil {
		log.Printf("Failed to change password: %v", err)
		return
	}

	fmt.Printf("✅ Password changed successfully\n")
}

// bindFederatedIdentityExample binds a third-party identity as an example
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
		log.Printf("Failed to bind federated identity: %v", err)
		return
	}

	fmt.Printf("✅ Successfully bound Google account\n")
}

// assignRoleExample assigns a role to an account as an example
func assignRoleExample(ctx context.Context, accountService service.AccountService) {
	accountID := "some-account-id"
	roleID := "admin-role-id"

	err := accountService.AssignRole(ctx, accountID, roleID)
	if err != nil {
		log.Printf("Failed to assign role: %v", err)
		return
	}

	fmt.Printf("✅ Role assigned successfully\n")
}

// softDeleteAccountExample soft-deletes an account as an example
func softDeleteAccountExample(ctx context.Context, accountService service.AccountService) {
	accountID := "some-account-id"

	err := accountService.SoftDeleteAccount(ctx, accountID)
	if err != nil {
		log.Printf("Failed to delete account: %v", err)
		return
	}

	fmt.Printf("✅ Account soft-deleted (data retained for auditing purposes)\n")
}
