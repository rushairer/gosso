package service

import "errors"

// Business rule violations returned by AccountService methods.
var (
	ErrUsernameAlreadyTaken          = errors.New("username already taken")
	ErrIncorrectOldPassword          = errors.New("incorrect old password")
	ErrFederatedIdentityAlreadyBound = errors.New("federated identity already bound")
	ErrEmailAlreadyRegistered        = errors.New("email already registered")
	ErrPhoneAlreadyRegistered        = errors.New("phone already registered")
	ErrAccountNotActive              = errors.New("account is not active")
)

// Dependency configuration errors for late-bound dependencies.
var (
	ErrSessionRevokerNotBound      = errors.New("SessionRevoker not configured; cannot revoke sessions")
	ErrOAuth2ClientDeleterNotBound = errors.New("OAuth2ClientDeleter not configured; cannot cascade-delete OAuth2 clients")
)
