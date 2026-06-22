package service

import "errors"

var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked, try again later")
	ErrIPLocked           = errors.New("too many attempts from this IP, try again later")
	ErrMFARateLimited     = errors.New("too many MFA attempts, try again later")
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

	// Passkey/WebAuthn errors
	ErrChallengeNotFound   = errors.New("challenge not found or expired")
	ErrPasskeyNotFound     = errors.New("no passkey found for account")
	ErrRequestBodyTooLarge = errors.New("request body too large")
	ErrCredentialOwnership = errors.New("credential does not belong to account")

	// Password reset errors
	ErrPasswordResetInvalidToken = errors.New("invalid or expired reset token")
	ErrPasswordResetExhausted    = errors.New("reset token exhausted, please request a new one")
	ErrPasswordCooldown          = errors.New("please wait before requesting another reset")

	// Verification errors
	ErrIdentifierNotAssociated  = errors.New("identifier not associated with this account")
	ErrVerificationCodeMismatch = errors.New("verification code does not belong to this account")

	// Registration errors
	ErrFailedToCreateAccount     = errors.New("failed to create account")
	ErrUnsupportedCredentialType = errors.New("unsupported credential type")

	// TOTP / crypto errors
	ErrNoPendingTOTPEnrollment = errors.New("no pending TOTP enrollment found")
	ErrCiphertextTooShort      = errors.New("ciphertext too short")

	// Configuration errors
	ErrInvalidConfig = errors.New("invalid configuration")
)
