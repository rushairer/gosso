//go:build !mysql && !postgres && !sqlite
// +build !mysql,!postgres,!sqlite

package database

import "log"

func NewDatabaseFactory() DatabaseFactory {
	log.Fatal("No database driver compiled. Use -tags mysql or -tags postgres or -tags sqlite")
	return nil
}
