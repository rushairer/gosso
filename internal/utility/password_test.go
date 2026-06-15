package utility

import "testing"

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ValidP@ssw0rd!", false},
		{"Short1A", true},          // too short
		{"alllowercase1A!", false}, // valid: has upper 'A', lower, digit '1', special '!', 16 chars
		{"ALLUPPERCASE1A", true},   // no lowercase
		{"NoDigitHereAa!", true},   // no digit
		{"1234567890Aa", true},     // no special character
		{"", true},                 // empty
		{"Ab1", true},              // too short
		{"Abcdefghij1", true},      // 11 chars, below minimum
		{"Abcdefghij1K", true},     // no special character
		{"!@#$%^&*Aa1x", false},    // special chars ok, 12 chars
		{"Short1Ab", true},         // 8 chars, below new minimum
		{"Abcdefghij1!", false},    // valid: upper+lower+digit+special, 12 chars
		{"N0SpecialHere", true},    // no special character
		// Unicode symbols must be rejected — they are not in the allowed set
		{"Abcdefghij1★", true}, // Unicode star symbol (IsSymbol)
		{"Abcdefghij1€", true}, // Euro sign (IsSymbol)
		{"Abcdefghij1©", true}, // Copyright sign (IsSymbol)
		// Standard special characters from the whitelist must be accepted
		{"Abcdefghij1#", false}, // hash
		{"Abcdefghij1(", false}, // parenthesis
		{"Abcdefghij1[", false}, // bracket
		{"Abcdefghij1,", false}, // comma
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}
