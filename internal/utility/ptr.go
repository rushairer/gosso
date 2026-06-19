package utility

// StringPtr returns a pointer to the given string value.
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
func Int64Ptr(v int64) *int64 {
	return &v
}
