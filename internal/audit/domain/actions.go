package domain

const (
	// Auth actions
	ActionLoginSuccess    = "auth.login.success"
	ActionLoginFailure    = "auth.login.failure"
	ActionMFALoginSuccess = "auth.mfa_login.success"
	ActionMFALoginFailure = "auth.mfa_login.failure"
	ActionLogout          = "auth.logout"

	// Account actions
	ActionAccountRegister = "account.register"
	ActionAccountUpdate   = "account.update"
	ActionAccountDelete   = "account.delete"
	ActionAccountSuspend  = "account.suspend"
	ActionAccountActivate = "account.activate"
	ActionPasswordChange  = "account.password.change"
	ActionPasswordReset   = "account.password.reset"

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
	ActionPasskeyRegister = "auth.passkey.register"
	ActionPasskeyLogin    = "auth.passkey.login"
	ActionPasskeyDelete   = "auth.passkey.delete"
)
