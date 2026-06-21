package utility

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPtr(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		p := Ptr("hello")
		assert.NotNil(t, p)
		assert.Equal(t, "hello", *p)
	})

	t.Run("empty string", func(t *testing.T) {
		p := Ptr("")
		assert.NotNil(t, p)
		assert.Equal(t, "", *p)
	})

	t.Run("unicode string", func(t *testing.T) {
		p := Ptr("你好世界")
		assert.NotNil(t, p)
		assert.Equal(t, "你好世界", *p)
	})

	t.Run("int64", func(t *testing.T) {
		p := Ptr(int64(42))
		assert.NotNil(t, p)
		assert.Equal(t, int64(42), *p)
	})

	t.Run("int64 zero", func(t *testing.T) {
		p := Ptr(int64(0))
		assert.NotNil(t, p)
		assert.Equal(t, int64(0), *p)
	})

	t.Run("bool", func(t *testing.T) {
		p := Ptr(true)
		assert.NotNil(t, p)
		assert.Equal(t, true, *p)
	})
}

func TestDerefString(t *testing.T) {
	t.Run("non-nil", func(t *testing.T) {
		s := "hello"
		assert.Equal(t, "hello", DerefString(&s))
	})

	t.Run("nil", func(t *testing.T) {
		assert.Equal(t, "", DerefString(nil))
	})

	t.Run("empty", func(t *testing.T) {
		s := ""
		assert.Equal(t, "", DerefString(&s))
	})
}
