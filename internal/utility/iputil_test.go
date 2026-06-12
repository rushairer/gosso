package utility

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeIP_ValidIPv4(t *testing.T) {
	assert.Equal(t, "192.168.1.1", NormalizeIP("192.168.1.1"))
	assert.Equal(t, "10.0.0.1", NormalizeIP("10.0.0.1"))
	assert.Equal(t, "127.0.0.1", NormalizeIP("127.0.0.1"))
}

func TestNormalizeIP_ValidIPv6(t *testing.T) {
	assert.Equal(t, "::1", NormalizeIP("::1"))
	assert.Equal(t, "2001:db8::1", NormalizeIP("2001:db8::1"))
	assert.Equal(t, "fe80::1", NormalizeIP("fe80::1"))
}

func TestNormalizeIP_Invalid(t *testing.T) {
	assert.Equal(t, "invalid", NormalizeIP("not-an-ip"))
	assert.Equal(t, "invalid", NormalizeIP(""))
	assert.Equal(t, "invalid", NormalizeIP("999.999.999.999"))
	assert.Equal(t, "invalid", NormalizeIP("192.168.1.1:8080"))
}
