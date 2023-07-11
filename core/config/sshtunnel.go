package config

import "github.com/rushairer/gosso/core/utilities"

var SSHTunnelHost string = utilities.GetEnv(
	"SSH_TUNNEL_HOST",
	"ssh_host",
)

var SSHTunnelPort string = utilities.GetEnv(
	"SSH_TUNNEL_PORT",
	"22",
)

var SSHTunnelUser string = utilities.GetEnv(
	"SSH_TUNNEL_USER",
	"root",
)

var SSHTunnelPassword string = utilities.GetEnv(
	"SSH_TUNNEL_PASSWORD",
	"",
)

var SSHTunnelPrivateKey string = utilities.GetEnv(
	"SSH_TUNNEL_PRIVATE_KEY",
	"private_key.pem",
)
