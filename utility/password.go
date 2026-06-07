package utility

import (
	"errors"
	"fmt"
	"unicode"
)

// MinPasswordLength is the minimum required password length.
const MinPasswordLength = 8

// MaxPasswordLength is the maximum allowed password length.
// bcrypt is preceded by SHA-256 so the 72-byte bcrypt limit no longer applies;
// this cap prevents excessive CPU/memory usage from oversized inputs.
const MaxPasswordLength = 1024

// ValidatePasswordStrength checks that a password meets minimum strength requirements:
// at least 8 bytes, with at least one uppercase letter, one lowercase letter, and one digit.
func ValidatePasswordStrength(password string) error {
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password must not exceed %d bytes", MaxPasswordLength)
	}
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d bytes", MinPasswordLength)
	}

	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return errors.New("password must contain uppercase, lowercase, and digit")
	}

	return nil
}
