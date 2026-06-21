package utility

// Ptr returns a pointer to the given value. Useful for obtaining a pointer
// to a literal or temporary value without declaring a local variable.
func Ptr[T any](v T) *T {
	return &v
}

// DerefString returns the value behind s, or "" if s is nil.
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
