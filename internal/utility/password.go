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
// Capped at 72 bytes to prevent excessive Argon2id memory/CPU usage from oversized
// inputs. Argon2id has no hard 72-byte limit (unlike bcrypt), but passwords longer
// than 72 bytes provide negligible entropy gain while significantly increasing
// computation cost (64 MiB memory × proportional CPU time).
const MaxPasswordLength = 72

// allowedSpecialChars defines the set of accepted special characters in passwords.
// This restrictive whitelist avoids obscure Unicode symbols (combining marks, control
// characters, etc.) that are hard to type on mobile keyboards.
const allowedSpecialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\"

// ValidatePasswordStrength checks that a password meets minimum strength requirements.
// Length is measured in bytes (not runes) to match Argon2id input behavior.
// Requirements: at least 12 bytes, with at least one uppercase letter, one lowercase
// letter, one digit, and one special character from the allowed set.
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
