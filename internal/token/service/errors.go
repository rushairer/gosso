package service

import "errors"

var (
	ErrTokenRevoked = errors.New("token has been revoked")
	ErrInvalidToken = errors.New("invalid token claims")
)
