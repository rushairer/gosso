package config

import "github.com/rushairer/gosso/core/utilities"

var ServerPort string = utilities.GetEnv(
	"SERVER_PORT",
	"8080",
)

var IsDebug bool = utilities.GetEnvBool(
	"IS_DEBUG",
	false,
)

var HomePagePath string = utilities.GetEnv(
	"HOME_PAGE_PATH",
	"/authentication/profile",
)

var SignInPagePath string = utilities.GetEnv(
	"SIGN_IN_PATH",
	"/",
)
