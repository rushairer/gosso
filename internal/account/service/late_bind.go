package service

import "fmt"

// late_bind.go provides late-binding functions for cross-module dependencies.
//
// These functions are needed because AccountService must be created before
// AuthModule (which needs AccountService), but AccountService's cascade
// operations (e.g. SoftDeleteAccount) depend on SessionService and
// OAuth2ClientDeleter which are only available after AuthModule/OAuth2Module
// initialization.

// BindSessionRevoker sets the session revoker on an AccountService after construction.
// Returns an error if svc is not an *accountServiceImpl.
func BindSessionRevoker(svc AccountService, revoker SessionRevoker) error {
	impl, ok := svc.(*accountServiceImpl)
	if !ok {
		return fmt.Errorf("BindSessionRevoker: svc is not *accountServiceImpl")
	}
	impl.setSessionRevoker(revoker)
	return nil
}

// BindOAuth2ClientDeleter sets the OAuth2 client deleter on an AccountService after construction.
// Returns an error if svc is not an *accountServiceImpl.
func BindOAuth2ClientDeleter(svc AccountService, deleter OAuth2ClientDeleter) error {
	impl, ok := svc.(*accountServiceImpl)
	if !ok {
		return fmt.Errorf("BindOAuth2ClientDeleter: svc is not *accountServiceImpl")
	}
	impl.setOAuth2ClientDeleter(deleter)
	return nil
}
