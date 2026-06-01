package domain

import "time"

// Consent 用户对 OAuth2 客户端的授权同意记录
type Consent struct {
	AccountID string    `json:"account_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
}
