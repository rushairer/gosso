//go:build !mysql && !postgres && !sqlite
// +build !mysql,!postgres,!sqlite

package utility

import (
	"log"

	"gorm.io/gorm"
)

func NewTestDB() *gorm.DB {
	log.Fatal("No database engine compiled. Use -tags mysql or -tags postgres or -tags sqlite")
	return nil
}
