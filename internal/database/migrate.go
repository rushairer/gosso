package database

import (
	"gosso/internal/domain/account"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&account.Account{},
		&account.Email{},
		&account.Phone{},
		&account.Profile{},
	)
}

func CleanMigrate(db *gorm.DB) error {
	return db.Migrator().DropTable(
		&account.Account{},
		&account.Email{},
		&account.Phone{},
		&account.Profile{},
	)
}
