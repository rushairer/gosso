package service

import "errors"

var (
	ErrTokenRevoked         = errors.New("token has been revoked")
	ErrInvalidToken         = errors.New("invalid token claims")
	ErrBlacklistUnavailable = errors.New("token blacklist unavailable")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
)
