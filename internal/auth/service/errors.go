package service

import "errors"

var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountNotActive   = errors.New("account is not active")
	ErrAccountLocked      = errors.New("account locked, try again later")

	// MFA errors
	ErrInvalidMFAToken      = errors.New("invalid or expired MFA token")
	ErrInvalidMFATokenScope = errors.New("invalid MFA token scope")
	ErrInvalidMFACode       = errors.New("invalid MFA code")
	ErrPasskeyNotAvailable  = errors.New("passkey not available")
	ErrPasskeyNotVerified   = errors.New("passkey verification not completed")

	// Session errors
	ErrSessionInvalid  = errors.New("session invalid")
	ErrAccountNotFound = errors.New("account not found")

	// Token errors
	ErrInvalidRefreshToken = errors.New("invalid refresh token")

	// General input errors
	ErrInvalidSessionID = errors.New("invalid session id")
)
