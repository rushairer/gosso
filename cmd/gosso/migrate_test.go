package gosso

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSteps(t *testing.T) {
	t.Run("valid positive number", func(t *testing.T) {
		steps, err := parseSteps("5")
		assert.NoError(t, err)
		assert.Equal(t, 5, steps)
	})

	t.Run("valid large number", func(t *testing.T) {
		steps, err := parseSteps("1000")
		assert.NoError(t, err)
		assert.Equal(t, 1000, steps)
	})

	t.Run("one", func(t *testing.T) {
		steps, err := parseSteps("1")
		assert.NoError(t, err)
		assert.Equal(t, 1, steps)
	})

	t.Run("zero returns error", func(t *testing.T) {
		_, err := parseSteps("0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "steps must be positive number")
	})

	t.Run("negative number returns error", func(t *testing.T) {
		_, err := parseSteps("-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "steps must be positive number")
	})

	t.Run("non-numeric string returns error", func(t *testing.T) {
		_, err := parseSteps("abc")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid steps number")
	})

	t.Run("empty string returns error", func(t *testing.T) {
		_, err := parseSteps("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid steps number")
	})

	t.Run("float string returns error", func(t *testing.T) {
		_, err := parseSteps("3.5")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid steps number")
	})
}

func TestParseVersion(t *testing.T) {
	t.Run("valid positive number", func(t *testing.T) {
		version, err := parseVersion("42")
		assert.NoError(t, err)
		assert.Equal(t, 42, version)
	})

	t.Run("zero is valid", func(t *testing.T) {
		version, err := parseVersion("0")
		assert.NoError(t, err)
		assert.Equal(t, 0, version)
	})

	t.Run("large version", func(t *testing.T) {
		version, err := parseVersion("99999")
		assert.NoError(t, err)
		assert.Equal(t, 99999, version)
	})

	t.Run("negative number returns error", func(t *testing.T) {
		_, err := parseVersion("-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "version must be non-negative")
	})

	t.Run("non-numeric string returns error", func(t *testing.T) {
		_, err := parseVersion("abc")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version number")
	})

	t.Run("empty string returns error", func(t *testing.T) {
		_, err := parseVersion("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version number")
	})

	t.Run("float string returns error", func(t *testing.T) {
		_, err := parseVersion("1.5")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version number")
	})
}
