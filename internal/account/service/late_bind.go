package service

// late_bind.go provides late-binding functions for cross-module dependencies.
//
// These functions are needed because AccountService must be created before
// AuthModule (which needs AccountService), but AccountService's cascade
// operations (e.g. SoftDeleteAccount) depend on SessionService and
// OAuth2ClientDeleter which are only available after AuthModule/OAuth2Module
// initialization.

// BindSessionRevoker sets the session revoker on an AccountService after construction.
// Panics if svc is not an *accountServiceImpl (should never happen in production).
func BindSessionRevoker(svc AccountService, revoker SessionRevoker) {
	impl, ok := svc.(*accountServiceImpl)
	if !ok {
		panic("BindSessionRevoker: svc is not *accountServiceImpl")
	}
	impl.setSessionRevoker(revoker)
}

// BindOAuth2ClientDeleter sets the OAuth2 client deleter on an AccountService after construction.
// Panics if svc is not an *accountServiceImpl (should never happen in production).
func BindOAuth2ClientDeleter(svc AccountService, deleter OAuth2ClientDeleter) {
	impl, ok := svc.(*accountServiceImpl)
	if !ok {
		panic("BindOAuth2ClientDeleter: svc is not *accountServiceImpl")
	}
	impl.setOAuth2ClientDeleter(deleter)
}
