package utility

import "testing"

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"user@example.com", "u***@e***.com"},
		{"ab@cd.org", "a***@c***.org"},
		{"x@y.io", "x***@y***.io"},
		{"noatsign", "n***"},
		{"a", "***"},
		{"", "***"},
		{"test@nodot", "t***@n***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := MaskEmail(tt.input)
			if got != tt.want {
				t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskPhone(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"13800138000", "138***00"},
		{"12345", "123***45"},
		{"1234", "***"},
		{"123", "***"},
		{"", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := MaskPhone(tt.input)
			if got != tt.want {
				t.Errorf("MaskPhone(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskIdentifier(t *testing.T) {
	tests := []struct {
		credType   string
		identifier string
		want       string
	}{
		{"email", "user@example.com", "u***@e***.com"},
		{"phone", "13800138000", "138***00"},
		{"unknown", "something", "***"},
		{"", "", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.credType+"/"+tt.identifier, func(t *testing.T) {
			got := MaskIdentifier(tt.credType, tt.identifier)
			if got != tt.want {
				t.Errorf("MaskIdentifier(%q, %q) = %q, want %q", tt.credType, tt.identifier, got, tt.want)
			}
		})
	}
}

func TestMaskOpaqueID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1234567890abcdef", "1234***cdef"},
		{"123456789", "1234***6789"},
		{"12345678", "***"},
		{"", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := MaskOpaqueID(tt.input)
			if got != tt.want {
				t.Errorf("MaskOpaqueID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
