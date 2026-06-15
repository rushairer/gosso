package utility

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// MinPasswordLength is the minimum required password length.
const MinPasswordLength = 12

// MaxPasswordLength is the maximum allowed password length.
// Argon2id has no 72-byte limit (unlike bcrypt), but this cap prevents
// excessive CPU/memory usage from oversized inputs.
const MaxPasswordLength = 1024

// allowedSpecialChars defines the set of accepted special characters in passwords.
// This restrictive whitelist avoids obscure Unicode symbols (combining marks, control
// characters, etc.) that are hard to type on mobile keyboards.
const allowedSpecialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\"

// ValidatePasswordStrength checks that a password meets minimum strength requirements:
// at least 12 bytes, with at least one uppercase letter, one lowercase letter, one digit, and one special character.
func ValidatePasswordStrength(password string) error {
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password must not exceed %d bytes", MaxPasswordLength)
	}
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d bytes", MinPasswordLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case strings.ContainsRune(allowedSpecialChars, c):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain uppercase, lowercase, digit, and special character")
	}

	return nil
}
