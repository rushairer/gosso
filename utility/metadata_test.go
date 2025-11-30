package utility

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMetadataHelper_GetString(t *testing.T) {
	data := map[string]any{
		"name": "John Doe",
		"age":  30,
	}
	helper := NewMetadataHelper(data)

	// 存在的字符串
	assert.Equal(t, "John Doe", helper.GetString("name", "default"))

	// 不存在的键
	assert.Equal(t, "default", helper.GetString("email", "default"))

	// 类型不匹配
	assert.Equal(t, "default", helper.GetString("age", "default"))
}

func TestMetadataHelper_GetInt(t *testing.T) {
	data := map[string]any{
		"age":      30,
		"level":    int64(5),
		"score":    95.5,
		"invalid":  "not a number",
	}
	helper := NewMetadataHelper(data)

	assert.Equal(t, 30, helper.GetInt("age", 0))
	assert.Equal(t, 5, helper.GetInt("level", 0))
	assert.Equal(t, 95, helper.GetInt("score", 0)) // float64 转 int
	assert.Equal(t, 0, helper.GetInt("invalid", 0))
	assert.Equal(t, 100, helper.GetInt("missing", 100))
}

func TestMetadataHelper_GetBool(t *testing.T) {
	data := map[string]any{
		"active":  true,
		"invalid": "yes",
	}
	helper := NewMetadataHelper(data)

	assert.True(t, helper.GetBool("active", false))
	assert.False(t, helper.GetBool("invalid", false))
	assert.True(t, helper.GetBool("missing", true))
}

func TestMetadataHelper_GetStringSlice(t *testing.T) {
	data := map[string]any{
		"tags":    []string{"go", "backend", "api"},
		"numbers": []interface{}{"one", "two", "three"},
		"invalid": "not a slice",
	}
	helper := NewMetadataHelper(data)

	// 直接的 []string
	tags := helper.GetStringSlice("tags", nil)
	assert.Equal(t, []string{"go", "backend", "api"}, tags)

	// []interface{} 转换
	numbers := helper.GetStringSlice("numbers", nil)
	assert.Equal(t, []string{"one", "two", "three"}, numbers)

	// 类型不匹配
	defaultSlice := []string{"default"}
	invalid := helper.GetStringSlice("invalid", defaultSlice)
	assert.Equal(t, defaultSlice, invalid)
}

func TestMetadataHelper_GetMap(t *testing.T) {
	data := map[string]any{
		"settings": map[string]any{
			"theme": "dark",
			"lang":  "en",
		},
		"invalid": "not a map",
	}
	helper := NewMetadataHelper(data)

	settings := helper.GetMap("settings", nil)
	assert.Equal(t, "dark", settings["theme"])
	assert.Equal(t, "en", settings["lang"])

	defaultMap := map[string]any{"default": "value"}
	invalid := helper.GetMap("invalid", defaultMap)
	assert.Equal(t, defaultMap, invalid)
}

func TestMetadataHelper_GetTime(t *testing.T) {
	now := time.Now()
	timestamp := now.Unix()

	data := map[string]any{
		"created_at": timestamp,
		"invalid":    "not a timestamp",
	}
	helper := NewMetadataHelper(data)

	createdAt := helper.GetTime("created_at", time.Time{})
	assert.Equal(t, timestamp, createdAt.Unix())

	defaultTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	invalid := helper.GetTime("invalid", defaultTime)
	assert.Equal(t, defaultTime, invalid)
}

func TestMetadataHelper_SetAndHas(t *testing.T) {
	helper := NewMetadataHelper(nil)

	// Set
	helper.Set("name", "Alice")
	assert.True(t, helper.Has("name"))
	assert.Equal(t, "Alice", helper.GetString("name", ""))

	// Delete
	helper.Delete("name")
	assert.False(t, helper.Has("name"))
}

func TestGetStringValue(t *testing.T) {
	data := map[string]any{
		"name": "Bob",
		"age":  25,
	}

	assert.Equal(t, "Bob", GetStringValue(data, "name", "default"))
	assert.Equal(t, "default", GetStringValue(data, "email", "default"))
	assert.Equal(t, "default", GetStringValue(data, "age", "default"))
}

func TestGetIntValue(t *testing.T) {
	data := map[string]any{
		"age":   30,
		"level": float64(5),
		"name":  "Alice",
	}

	assert.Equal(t, 30, GetIntValue(data, "age", 0))
	assert.Equal(t, 5, GetIntValue(data, "level", 0))
	assert.Equal(t, 0, GetIntValue(data, "name", 0))
	assert.Equal(t, 100, GetIntValue(data, "missing", 100))
}

func TestSetIfNotEmpty(t *testing.T) {
	data := make(map[string]any)

	SetIfNotEmpty(data, "name", "Alice")
	SetIfNotEmpty(data, "email", "")

	assert.Equal(t, "Alice", data["name"])
	assert.NotContains(t, data, "email")
}

func TestSetIfNotZero(t *testing.T) {
	data := make(map[string]any)

	SetIfNotZero(data, "age", 30)
	SetIfNotZero(data, "level", 0)

	assert.Equal(t, 30, data["age"])
	assert.NotContains(t, data, "level")
}

func TestMetadataHelper_NilData(t *testing.T) {
	helper := NewMetadataHelper(nil)
	
	// 应该不会 panic
	assert.Equal(t, "default", helper.GetString("key", "default"))
	assert.Equal(t, 0, helper.GetInt("key", 0))
	assert.False(t, helper.Has("key"))
	
	// 应该可以设置值
	helper.Set("name", "test")
	assert.Equal(t, "test", helper.GetString("name", ""))
}

func TestMetadataHelper_GetAll(t *testing.T) {
	data := map[string]any{
		"name": "Alice",
		"age":  30,
	}
	helper := NewMetadataHelper(data)

	all := helper.GetAll()
	assert.Equal(t, 2, len(all))
	assert.Equal(t, "Alice", all["name"])
	assert.Equal(t, 30, all["age"])
}
