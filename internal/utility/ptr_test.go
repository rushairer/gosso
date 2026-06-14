package utility

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringPtr(t *testing.T) {
	t.Run("normal string", func(t *testing.T) {
		p := StringPtr("hello")
		assert.NotNil(t, p)
		assert.Equal(t, "hello", *p)
	})

	t.Run("empty string", func(t *testing.T) {
		p := StringPtr("")
		assert.NotNil(t, p)
		assert.Equal(t, "", *p)
	})

	t.Run("unicode", func(t *testing.T) {
		p := StringPtr("你好世界")
		assert.NotNil(t, p)
		assert.Equal(t, "你好世界", *p)
	})
}
