package utility

import "time"

// MetadataHelper 提供安全的 Metadata 访问方法
type MetadataHelper struct {
	data map[string]any
}

// NewMetadataHelper 创建 Metadata 辅助工具
func NewMetadataHelper(data map[string]any) *MetadataHelper {
	if data == nil {
		data = make(map[string]any)
	}
	return &MetadataHelper{data: data}
}

// GetString 获取字符串值
func (m *MetadataHelper) GetString(key string, defaultValue string) string {
	if v, ok := m.data[key].(string); ok {
		return v
	}
	return defaultValue
}

// GetInt 获取整数值（兼容 JSON 的 float64）
func (m *MetadataHelper) GetInt(key string, defaultValue int) int {
	switch v := m.data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return defaultValue
	}
}

// GetInt64 获取 int64 值
func (m *MetadataHelper) GetInt64(key string, defaultValue int64) int64 {
	switch v := m.data[key].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return defaultValue
	}
}

// GetFloat64 获取浮点数值
func (m *MetadataHelper) GetFloat64(key string, defaultValue float64) float64 {
	switch v := m.data[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return defaultValue
	}
}

// GetBool 获取布尔值
func (m *MetadataHelper) GetBool(key string, defaultValue bool) bool {
	if v, ok := m.data[key].(bool); ok {
		return v
	}
	return defaultValue
}

// GetStringSlice 获取字符串切片
func (m *MetadataHelper) GetStringSlice(key string, defaultValue []string) []string {
	if v, ok := m.data[key].([]string); ok {
		return v
	}
	// 尝试从 []interface{} 转换
	if v, ok := m.data[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return defaultValue
}

// GetMap 获取嵌套的 map
func (m *MetadataHelper) GetMap(key string, defaultValue map[string]any) map[string]any {
	if v, ok := m.data[key].(map[string]any); ok {
		return v
	}
	// 尝试从 map[string]interface{} 转换
	if v, ok := m.data[key].(map[string]interface{}); ok {
		result := make(map[string]any, len(v))
		for k, val := range v {
			result[k] = val
		}
		return result
	}
	return defaultValue
}

// GetTime 获取时间值（Unix 时间戳）
func (m *MetadataHelper) GetTime(key string, defaultValue time.Time) time.Time {
	timestamp := m.GetInt64(key, 0)
	if timestamp > 0 {
		return time.Unix(timestamp, 0)
	}
	return defaultValue
}

// Set 设置值
func (m *MetadataHelper) Set(key string, value any) {
	m.data[key] = value
}

// Has 检查键是否存在
func (m *MetadataHelper) Has(key string) bool {
	_, ok := m.data[key]
	return ok
}

// Delete 删除键
func (m *MetadataHelper) Delete(key string) {
	delete(m.data, key)
}

// GetAll 获取原始 map
func (m *MetadataHelper) GetAll() map[string]any {
	return m.data
}

// 独立的辅助函数，不依赖 MetadataHelper 结构体

// GetStringValue 从 map 中安全获取字符串值
func GetStringValue(m map[string]any, key, defaultValue string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultValue
}

// GetIntValue 从 map 中安全获取整数值
func GetIntValue(m map[string]any, key string, defaultValue int) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return defaultValue
	}
}

// GetBoolValue 从 map 中安全获取布尔值
func GetBoolValue(m map[string]any, key string, defaultValue bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return defaultValue
}

// GetFloat64Value 从 map 中安全获取浮点数值
func GetFloat64Value(m map[string]any, key string, defaultValue float64) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return defaultValue
	}
}

// SetIfNotEmpty 仅在值非空时设置
func SetIfNotEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// SetIfNotZero 仅在值非零时设置
func SetIfNotZero(m map[string]any, key string, value int) {
	if value != 0 {
		m[key] = value
	}
}
