package utility

import "strings"

// MaskEmail masks an email address for safe display.
// Example: "user@example.com" -> "u***@e***.com"
func MaskEmail(email string) string {
	atIdx := strings.Index(email, "@")
	if atIdx > 0 && atIdx < len(email)-1 {
		local := email[:atIdx]
		domain := email[atIdx+1:]
		maskedLocal := string(local[0]) + "***"
		dotIdx := strings.Index(domain, ".")
		var maskedDomain string
		if dotIdx > 0 {
			maskedDomain = string(domain[0]) + "***" + domain[dotIdx:]
		} else {
			maskedDomain = string(domain[0]) + "***"
		}
		return maskedLocal + "@" + maskedDomain
	}
	if len(email) > 1 {
		return string(email[0]) + "***"
	}
	return "***"
}

// MaskPhone masks a phone number for safe display.
// Example: "13800138000" -> "138***00"
func MaskPhone(phone string) string {
	if len(phone) > 4 {
		return phone[:3] + "***" + phone[len(phone)-2:]
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
