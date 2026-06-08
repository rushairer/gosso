package utility

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePhoneFormat(t *testing.T) {
	tests := []struct {
		name   string
		phone  string
		expect bool
	}{
		// Valid E.164-like numbers
		{"US", "+12025551234", true},
		{"UK", "+447911123456", true},
		{"China", "+8613800138000", true},
		{"Japan", "+81312345678", true},
		{"short_no_plus", "12025551234", true},
		{"min_digits", "+1234567", true},
		{"max_digits", "+123456789012345", true},

		// Invalid
		{"empty", "", false},
		{"letters", "+123abc456", false},
		{"too_short", "+123456", false},
		{"too_long", "+1234567890123456", false},
		{"leading_zero", "+0123456789", false},
		{"spaces", "+1 202 555 1234", false},
		{"dashes", "+1-202-555-1234", false},
		{"just_plus", "+", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidatePhoneFormat(tt.phone)
			assert.Equal(t, tt.expect, got, "phone=%q", tt.phone)
		})
	}
}
