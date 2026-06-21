package utility

import (
	"strings"
	"unicode/utf8"
)

// MaskEmail masks an email address for safe display.
// Example: "user@example.com" -> "u***@e***"
// The TLD is masked to avoid leaking organization type information.
func MaskEmail(email string) string {
	atIdx := strings.Index(email, "@")
	if atIdx > 0 && atIdx < len(email)-1 {
		local := []rune(email[:atIdx])
		domain := email[atIdx+1:]
		maskedLocal := string(local[0]) + "***"
		r, _ := utf8.DecodeRuneInString(domain)
		maskedDomain := string(r) + "***"
		return maskedLocal + "@" + maskedDomain
	}
	runes := []rune(email)
	if len(runes) > 1 {
		return string(runes[0]) + "***"
	}
	return "***"
}

// MaskPhone masks a phone number for safe display.
// Example: "13800138000" -> "138***00"
func MaskPhone(phone string) string {
	runes := []rune(phone)
	if len(runes) > 4 {
		return string(runes[:3]) + "***" + string(runes[len(runes)-2:])
	}
	return "***"
}

// MaskIdentifier masks an identifier based on its credential type.
func MaskIdentifier(credType, identifier string) string {
	switch credType {
	case "email":
		return MaskEmail(identifier)
	case "phone":
		return MaskPhone(identifier)
	default:
		return "***"
	}
}

// MaskOpaqueID masks an internal opaque identifier while keeping enough
// characters for log correlation.
// Uses byte slicing directly since opaque IDs (UUIDs) are ASCII-only,
// avoiding the []rune allocation on every log statement.
func MaskOpaqueID(id string) string {
	if len(id) <= 8 {
		return "***"
	}
	return id[:4] + "***" + id[len(id)-4:]
}

// MaskRateLimitKey masks PII (IP addresses, usernames) from rate limit keys for safe logging.
// Keeps only the first colon-separated segment (the key type/prefix).
// Example: "login_attempts:192.168.1.1:user@example.com" -> "login_attempts:***"
func MaskRateLimitKey(key string) string {
	for i, c := range key {
		if c == ':' {
			return key[:i] + ":***"
		}
	}
	return "***"
}
