package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// NewRecord creates an AuditRecord with auto-generated ID, TxID, and CreatedAt.
func NewRecord(action, actor string, accountID *uuid.UUID, resource, meta json.RawMessage) *AuditRecord {
	return &AuditRecord{
		ID:        uuid.New(),
		TxID:      uuid.New(),
		AccountID: accountID,
		Action:    action,
		Actor:     actor,
		Resource:  resource,
		Meta:      meta,
		CreatedAt: time.Now(),
	}
}
