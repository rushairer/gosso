package service

import "errors"

var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked, try again later")
	ErrIPLocked           = errors.New("too many attempts from this IP, try again later")
	ErrServiceUnavailable = errors.New("service temporarily unavailable")

	// MFA errors
	ErrInvalidMFAToken      = errors.New("invalid or expired MFA token")
	ErrInvalidMFATokenScope = errors.New("invalid MFA token scope")
	ErrInvalidMFACode       = errors.New("invalid MFA code")
	ErrUnsupportedMFAType   = errors.New("unsupported MFA type")
	ErrPasskeyNotAvailable  = errors.New("passkey not available")
	ErrPasskeyNotVerified   = errors.New("passkey verification not completed")

	// Session errors
	ErrSessionInvalid = errors.New("session invalid")

	// Token errors
	ErrInvalidRefreshToken = errors.New("invalid refresh token")

	// General input errors
	ErrInvalidSessionID = errors.New("invalid session id")

	// Passkey/WebAuthn errors
	ErrChallengeNotFound   = errors.New("challenge not found or expired")
	ErrPasskeyNotFound     = errors.New("no passkey found for account")
	ErrRequestBodyTooLarge = errors.New("request body too large")
	ErrCredentialOwnership = errors.New("credential does not belong to account")

	// Social login errors
	ErrUnsupportedProvider = errors.New("unsupported provider")

	// Password reset errors
	ErrPasswordResetInvalidToken = errors.New("invalid or expired reset token")
	ErrPasswordResetExhausted    = errors.New("reset token exhausted, please request a new one")
)
