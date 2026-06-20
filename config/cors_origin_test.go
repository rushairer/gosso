package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCORSOrigin_StrictOriginOnly(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		wantErr string
	}{
		{name: "https origin", origin: "https://sso.example.com"},
		{name: "https origin with port", origin: "https://sso.example.com:8443"},
		{name: "wildcard", origin: "*"},
		{name: "missing scheme", origin: "sso.example.com", wantErr: "must be a full URL"},
		{name: "path rejected", origin: "https://sso.example.com/app", wantErr: "must not include path"},
		{name: "query rejected", origin: "https://sso.example.com?foo=bar", wantErr: "must not include path"},
		{name: "fragment rejected", origin: "https://sso.example.com#frag", wantErr: "must not include path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCORSOrigin(tt.origin)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
