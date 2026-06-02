package utility

import "time"

// MetadataHelper provides safe access methods to metadata
type MetadataHelper struct {
	data map[string]any
}

// NewMetadataHelper creates a Metadata helper tool
func NewMetadataHelper(data map[string]any) *MetadataHelper {
	if data == nil {
		data = make(map[string]any)
	}
	return &MetadataHelper{data: data}
}

// GetString gets string value
func (m *MetadataHelper) GetString(key string, defaultValue string) string {
	if v, ok := m.data[key].(string); ok {
		return v
	}
	return defaultValue
}

// GetInt gets integer value (compatible with JSON float64)
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

// GetInt64 gets int64 value
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

// GetFloat64 gets float64 value
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

// GetBool gets boolean value
func (m *MetadataHelper) GetBool(key string, defaultValue bool) bool {
	if v, ok := m.data[key].(bool); ok {
		return v
	}
	return defaultValue
}

// GetStringSlice gets string slice
func (m *MetadataHelper) GetStringSlice(key string, defaultValue []string) []string {
	if v, ok := m.data[key].([]string); ok {
		return v
	}
	// Try converting from []interface{}
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

// GetMap gets nested map
func (m *MetadataHelper) GetMap(key string, defaultValue map[string]any) map[string]any {
	if v, ok := m.data[key].(map[string]any); ok {
		return v
	}
	// Try converting from map[string]interface{}
	if v, ok := m.data[key].(map[string]interface{}); ok {
		result := make(map[string]any, len(v))
		for k, val := range v {
			result[k] = val
		}
		return result
	}
	return defaultValue
}

// GetTime gets time value (Unix timestamp)
func (m *MetadataHelper) GetTime(key string, defaultValue time.Time) time.Time {
	timestamp := m.GetInt64(key, 0)
	if timestamp > 0 {
		return time.Unix(timestamp, 0)
	}
	return defaultValue
}

// Set sets value
func (m *MetadataHelper) Set(key string, value any) {
	m.data[key] = value
}

// Has checks if key exists
func (m *MetadataHelper) Has(key string) bool {
	_, ok := m.data[key]
	return ok
}

// Delete deletes a key
func (m *MetadataHelper) Delete(key string) {
	delete(m.data, key)
}

// GetAll gets the raw map
func (m *MetadataHelper) GetAll() map[string]any {
	return m.data
}

// Standalone helper functions, independent of MetadataHelper struct

// GetStringValue safely gets a string value from a map
func GetStringValue(m map[string]any, key, defaultValue string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultValue
}

// GetIntValue safely gets an integer value from a map
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

// GetBoolValue safely gets a boolean value from a map
func GetBoolValue(m map[string]any, key string, defaultValue bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return defaultValue
}

// GetFloat64Value safely gets a float64 value from a map
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

// SetIfNotEmpty sets value only when not empty
func SetIfNotEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// SetIfNotZero sets value only when not zero
func SetIfNotZero(m map[string]any, key string, value int) {
	if value != 0 {
		m[key] = value
	}
}
