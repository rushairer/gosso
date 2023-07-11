package sshtunnel

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func NewSSHClient(
	sshHost, sshPort, sshUser, sshPass, privateKey string,
) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	key, err := os.ReadFile(privateKey)
	if err != nil {
		log.Fatalf("Unable to read private key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if signer != nil {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return []ssh.Signer{signer}, err
		}))
	}

	if sshPass != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PasswordCallback(func() (string, error) {
			return sshPass, nil
		}))
	}

	return ssh.Dial("tcp", fmt.Sprintf("%s:%s", sshHost, sshPort), sshConfig)
}
