package domain

import (
	"encoding/json"
	"time"
)

type AuditRecord struct {
	ID        string          `json:"id"`
	TxID      string          `json:"tx_id"`
	AccountID *string         `json:"account_id,omitempty"`
	Action    string          `json:"action"`
	Actor     string          `json:"actor"`
	Resource  json.RawMessage `json:"resource"`
	Old       json.RawMessage `json:"old,omitempty"`
	New       json.RawMessage `json:"new,omitempty"`
	Meta      json.RawMessage `json:"meta,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type AuditEntry struct {
	ID        string          `json:"id"`
	TxID      string          `json:"tx_id"`
	AccountID *string         `json:"account_id,omitempty"`
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	Attempts  uint            `json:"attempts"`
	LastError *string         `json:"last_error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}
