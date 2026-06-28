package service

// Scope constants for JWT token claims.
const (
	// ScopeMFA is the JWT scope for MFA verification tokens.
	ScopeMFA = "mfa"
	// ScopeAdmin is required on OAuth access tokens used for admin APIs.
	ScopeAdmin = "admin"
)

// Role constants for RBAC.
const (
	// RoleAdmin is the administrator role name.
	RoleAdmin = "admin"
)
