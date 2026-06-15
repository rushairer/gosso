package utility

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBigEndianBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected []byte
	}{
		{"zero", 0, []byte{0}},
		{"one", 1, []byte{1}},
		{"127", 127, []byte{127}},
		{"128", 128, []byte{128}},
		{"255", 255, []byte{255}},
		{"256", 256, []byte{1, 0}},
		{"65537", 65537, []byte{1, 0, 1}}, // common RSA exponent
		{"3", 3, []byte{3}},
		{"1000", 1000, []byte{3, 232}}, // 0x03E8
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, BigEndianBytes(tt.input))
		})
	}
}
