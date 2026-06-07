package utility

import "testing"

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ValidP@ssw0rd!", false},
		{"Short1A", true},               // too short
		{"alllowercase1A", false},       // valid: has upper 'A', lower, digit '1', 15 chars
		{"ALLUPPERCASE1A", true},        // no lowercase
		{"NoDigitHereAa", true},         // no digit
		{"1234567890Aa", false},         // valid: 12 chars
		{"", true},                      // empty
		{"Ab1", true},                   // too short
		{"Abcdefghij1", true},           // 11 chars, below minimum
		{"Abcdefghij1K", false},         // valid: upper+lower+digit, 12 chars
		{"!@#$%^&*Aa1x", false},         // special chars ok, 12 chars
		{"Short1Ab", true},              // 8 chars, below new minimum
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
