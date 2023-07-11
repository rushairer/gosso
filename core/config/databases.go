package config

import "github.com/rushairer/gosso/core/utilities"

var MysqlDSN string = utilities.GetEnv(
	"MYSQL_DSN",
	"root:123456@(127.0.0.1:30306)/sso?parseTime=true",
)

var SessionSecret string = utilities.GetEnv(
	"SESSION_SECRET",
	"sso-session-secret",
)
