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

	// Passkey/WebAuthn errors
	ErrChallengeNotFound   = errors.New("challenge not found or expired")
	ErrPasskeyNotFound     = errors.New("no passkey found for account")
	ErrRequestBodyTooLarge = errors.New("request body too large")
	ErrCredentialNotFound  = errors.New("credential not found")
	ErrCredentialOwnership = errors.New("credential does not belong to account")

	// Social login errors
	ErrUnsupportedProvider = errors.New("unsupported provider")
)

// Scope constants for JWT token claims
const ScopeMFA = "mfa"

// Role constants for RBAC
const RoleAdmin = "admin"
