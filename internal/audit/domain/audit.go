package domain

import (
	"encoding/json"
	"time"
)

// AuditRecord represents a single audit-log entry stored in the database.
type AuditRecord struct {
	ID            string          `json:"id"`
	CorrelationID string          `json:"tx_id"` // Random UUID for grouping related records; not a DB transaction ID
	AccountID     *string         `json:"account_id,omitempty"`
	Action        string          `json:"action"`
	Actor         string          `json:"actor"`
	Resource      json.RawMessage `json:"resource"`
	Old           json.RawMessage `json:"old,omitempty"`
	New           json.RawMessage `json:"new,omitempty"`
	Meta          json.RawMessage `json:"meta,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}
