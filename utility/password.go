package utility

import (
	"errors"
	"unicode"
)

// MinPasswordLength is the minimum required password length.
const MinPasswordLength = 8

// ValidatePasswordStrength checks that a password meets minimum strength requirements:
// at least 8 characters, with at least one uppercase letter, one lowercase letter, and one digit.
func ValidatePasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return errors.New("password must be at least 8 characters")
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
