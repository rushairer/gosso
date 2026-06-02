package domain

import "time"

// Consent user authorization consent record for an OAuth2 client
type Consent struct {
	AccountID string    `json:"account_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
}
