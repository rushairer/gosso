package utility

import (
	"strings"
	"unicode/utf8"
)

// MaskEmail masks an email address for safe display.
// Example: "user@example.com" -> "u***@e***.com"
func MaskEmail(email string) string {
	atIdx := strings.Index(email, "@")
	if atIdx > 0 && atIdx < len(email)-1 {
		local := []rune(email[:atIdx])
		domain := email[atIdx+1:]
		maskedLocal := string(local[0]) + "***"
		dotIdx := strings.Index(domain, ".")
		var maskedDomain string
		if dotIdx > 0 {
			domainRunes := []rune(domain)
			prefixLen := len([]rune(domain[:dotIdx]))
			maskedDomain = string(domainRunes[0]) + "***" + string(domainRunes[prefixLen:])
		} else {
			r, _ := utf8.DecodeRuneInString(domain)
			maskedDomain = string(r) + "***"
		}
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
