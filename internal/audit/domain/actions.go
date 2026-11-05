package domain

const (
	// Auth actions
	ActionLoginSuccess     = "auth.login.success"
	ActionLoginFailure     = "auth.login.failure"
	ActionMFALoginSuccess  = "auth.mfa_login.success"
	ActionMFALoginFailure  = "auth.mfa_login.failure"
	ActionMFAStepUpSuccess = "auth.mfa_step_up.success"
	ActionMFAStepUpFailure = "auth.mfa_step_up.failure"
	ActionLogout           = "auth.logout"

	// Account actions
	ActionAccountRegister  = "account.register"
	ActionAccountUpdate    = "account.update"
	ActionAccountDelete    = "account.delete"
	ActionAccountSuspend   = "account.suspend"
	ActionAccountActivate  = "account.activate"
	ActionPasswordChange   = "account.password.change"
	ActionPasswordReset    = "account.password.reset"
	ActionCredentialVerify = "account.credential.verify"

	// Federated identity actions
	ActionFederatedIdentityBind   = "account.federated_identity.bind"
	ActionFederatedIdentityUnbind = "account.federated_identity.unbind"

	// Role actions
	ActionRoleAssign = "account.role.assign"
	ActionRoleRemove = "account.role.remove"

	// MFA actions
	ActionMFAActivate = "account.mfa.activate"
	ActionMFADisable  = "account.mfa.disable"

	// Passkey actions
	// #nosec G101 -- public audit event identifier, never credential material.
	ActionPasskeyRegister = "auth.passkey.register"
	// #nosec G101 -- public audit event identifier, never credential material.
	ActionPasskeyLogin = "auth.passkey.login"
	// #nosec G101 -- public audit event identifier, never credential material.
	ActionPasskeyDelete = "auth.passkey.delete"

	// Token lifecycle audit actions
	// #nosec G101 -- public audit event identifier, never credential material.
	ActionTokenRefresh = "auth.token.refresh"
	// #nosec G101 -- public audit event identifier, never credential material.
	ActionTokenRotate = "auth.token.rotate"
	// #nosec G101 -- public audit event identifier, never credential material.
	ActionTokenRevoke = "auth.token.revoke"

	// OAuth2 client management audit actions
	ActionOAuth2ClientRegister = "oauth2.client.register"
	ActionOAuth2ClientUpdate   = "oauth2.client.update"
	ActionOAuth2ClientDelete   = "oauth2.client.delete"
)
