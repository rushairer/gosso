package service

import "errors"

var (
	// ErrClientSecretRequired is returned when a confidential client omits the client_secret.
	ErrClientSecretRequired = errors.New("client_secret required")

	// ErrInvalidClientSecret is returned when the client_secret does not match the stored hash.
	ErrInvalidClientSecret = errors.New("invalid client_secret")

	// ErrClientAccessDenied is returned when an account attempts to operate on a client they do not own.
	ErrClientAccessDenied = errors.New("access denied: client does not belong to this account")

	// ErrRedisClientRequired is returned when an auth code service is initialized without Redis.
	ErrRedisClientRequired = errors.New("auth code service: redis client is required")

	// ErrConsentNil is returned when a nil consent object is passed to the consent service.
	ErrConsentNil = errors.New("consent must not be nil")

	// ErrReauthenticationRequired indicates re-authentication is required.
	ErrReauthenticationRequired = errors.New("reauthentication required")

	// ErrUnsupportedACR indicates the requested ACR is unsupported.
	ErrUnsupportedACR = errors.New("requested acr is not supported")

	// ErrInvalidMaxAge indicates max_age parameter is invalid.
	ErrInvalidMaxAge = errors.New("max_age must be a non-negative integer")
)

// ValidationError represents an OAuth2 input validation error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// IsValidationError checks if the error is an OAuth2 validation error.
func IsValidationError(err error) bool {
	var valErr *ValidationError
	return errors.As(err, &valErr)
}
