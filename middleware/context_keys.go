package middleware

const (
	// ContextKeyAccountID is the gin context key for the account ID.
	ContextKeyAccountID = "account_id"
	// ContextKeyClaims is the gin context key for the JWT claims.
	ContextKeyClaims = "jwt_claims"
	// ContextKeyLogger is the gin context key for the request-scoped zap logger
	// enriched with request_id. Use LoggerFromContext(ctx) to retrieve it.
	ContextKeyLogger = "logger"
)
