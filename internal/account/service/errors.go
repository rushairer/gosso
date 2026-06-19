package service

import "errors"

// Business rule violations returned by AccountService methods.
var (
	ErrUsernameAlreadyTaken          = errors.New("username already taken")
	ErrUsernameEmpty                 = errors.New("username must not be empty")
	ErrUsernameTooLong               = errors.New("username must not exceed 64 characters")
	ErrUsernameInvalidChars          = errors.New("username may only contain lowercase letters, digits, hyphens, dots, and underscores")
	ErrIncorrectOldPassword          = errors.New("incorrect old password")
	ErrFederatedIdentityAlreadyBound = errors.New("federated identity already bound")
	ErrEmailAlreadyRegistered        = errors.New("email already registered")
	ErrPhoneAlreadyRegistered        = errors.New("phone already registered")
	ErrAccountNotActive              = errors.New("account is not active")
	ErrCredentialAlreadyExists       = errors.New("credential already exists")
	ErrCannotUnbindLastAuthMethod    = errors.New("cannot unbind the only authentication method; set a password first")
)

// Dependency configuration errors for late-bound dependencies.
var (
	ErrSessionRevokerNotBound      = errors.New("SessionRevoker not configured; cannot revoke sessions")
	ErrOAuth2ClientDeleterNotBound = errors.New("OAuth2ClientDeleter not configured; cannot cascade-delete OAuth2 clients")
)
