package service

import "errors"

var (
	// 认证错误
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountNotActive   = errors.New("account is not active")
	ErrAccountLocked      = errors.New("account locked, try again later")

	// MFA 错误
	ErrMFARequired          = errors.New("MFA verification required")
	ErrInvalidMFAToken      = errors.New("invalid or expired MFA token")
	ErrInvalidMFATokenScope = errors.New("invalid MFA token scope")
	ErrInvalidMFACode       = errors.New("invalid MFA code")
	ErrPasskeyNotAvailable  = errors.New("passkey not available")
	ErrPasskeyNotVerified   = errors.New("passkey verification not completed")

	// 会话错误
	ErrSessionInvalid  = errors.New("session invalid")
	ErrAccountNotFound = errors.New("account not found")

	// 令牌错误
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenRevoked        = errors.New("token has been revoked")

	// 通用输入错误
	ErrInvalidSessionID = errors.New("invalid session id")
)
