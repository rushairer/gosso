package utility

import "testing"

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ValidP@ss1", false},
		{"Short1A", true},            // too short
		{"alllowercase1A", false},    // has upper? no - wait, this has no uppercase
		{"ALLUPPERCASE1A", true},     // no lowercase
		{"NoDigitHereAa", true},      // no digit
		{"12345678Aa", false},        // valid
		{"", true},                   // empty
		{"Ab1", true},                // too short
		{"Abcdefg1", false},          // valid: upper+lower+digit, 8 chars
		{"!@#$%^&*Aa1", false},       // special chars ok
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
