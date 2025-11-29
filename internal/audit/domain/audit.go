package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AuditRecord struct {
	ID        uuid.UUID       `json:"id"`
	TxID      uuid.UUID       `json:"tx_id"`
	AccountID *uuid.UUID      `json:"account_id,omitempty"`
	Action    string          `json:"action"`
	Actor     string          `json:"actor"`
	Resource  json.RawMessage `json:"resource"`
	Old       json.RawMessage `json:"old,omitempty"`
	New       json.RawMessage `json:"new,omitempty"`
	Meta      json.RawMessage `json:"meta,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}
