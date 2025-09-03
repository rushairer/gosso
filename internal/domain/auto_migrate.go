package domain

import (
	"gosso/internal/domain/account"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&account.Account{},
		&account.AccountEmail{},
		&account.AccountPhone{},
	)
}

func CleanMigrate(db *gorm.DB) error {
	return db.Migrator().DropTable(
		&account.Account{},
		&account.AccountEmail{},
		&account.AccountPhone{},
	)
}
