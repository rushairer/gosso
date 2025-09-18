//go:build !mysql && !postgres

package database

import "log"

func NewDatabaseFactory() DatabaseFactory {
	log.Fatal("No database driver compiled. Use -tags mysql or -tags postgres")
	return nil
}
