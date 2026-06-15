package service

import "errors"

// ValidationError indicates a client-side input validation error.
// Controllers should return HTTP 400 for this error type.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

// IsValidationError checks if err is or wraps a ValidationError.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}
