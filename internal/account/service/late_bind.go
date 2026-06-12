package service

// late_bind.go provides late-binding functions for cross-module dependencies.
//
// Deprecated: Use AccountService.SetSessionRevoker and
// AccountService.SetOAuth2ClientDeleter interface methods instead.
// These functions are kept for backward compatibility.

// BindSessionRevoker sets the session revoker on an AccountService after construction.
//
// Deprecated: Use svc.SetSessionRevoker(revoker) directly.
func BindSessionRevoker(svc AccountService, revoker SessionRevoker) {
	svc.SetSessionRevoker(revoker)
}

// BindOAuth2ClientDeleter sets the OAuth2 client deleter on an AccountService after construction.
//
// Deprecated: Use svc.SetOAuth2ClientDeleter(deleter) directly.
func BindOAuth2ClientDeleter(svc AccountService, deleter OAuth2ClientDeleter) {
	svc.SetOAuth2ClientDeleter(deleter)
}
