package databases

import (
	"log"
	"testing"

	"github.com/rushairer/gosso/core/config"
	"github.com/stretchr/testify/assert"
)

func TestDatabasesConfig(t *testing.T) {
	mysqlDsn := config.MysqlDSN
	assert.NotEmpty(t, mysqlDsn)
	log.Println(mysqlDsn)

	sessionSecret := config.SessionSecret

	assert.NotEmpty(t, sessionSecret)
	log.Println(sessionSecret)
}
