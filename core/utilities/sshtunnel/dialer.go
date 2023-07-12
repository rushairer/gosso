package sshtunnel

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"
)

type ViaSSHDialer struct {
	client *ssh.Client
}

func (d *ViaSSHDialer) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	return d.client.Dial("tcp", address)
}

func NewViaSSHDialer(client *ssh.Client) *ViaSSHDialer {
	return &ViaSSHDialer{client}
}
