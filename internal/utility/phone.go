package utility

import "regexp"

var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{6,14}$`)

// ValidatePhoneFormat checks if the given phone number matches E.164-like format.
func ValidatePhoneFormat(phone string) bool {
	return phoneRegex.MatchString(phone)
}
