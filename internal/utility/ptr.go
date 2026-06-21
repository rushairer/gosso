package utility

// Ptr returns a pointer to the given value. Useful for obtaining a pointer
// to a literal or temporary value without declaring a local variable.
func Ptr[T any](v T) *T {
	return &v
}

// StringPtr returns a pointer to the given string value.
//
// Deprecated: Use Ptr[string](s) instead.
func StringPtr(s string) *string {
	return &s
}

// DerefString returns the value behind s, or "" if s is nil.
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Int64Ptr returns a pointer to the given int64 value.
//
// Deprecated: Use Ptr[int64](v) instead.
func Int64Ptr(v int64) *int64 {
	return &v
}
