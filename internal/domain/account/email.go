package account

import (
	"time"

	"github.com/google/uuid"
)

type Email struct {
	Address    string     `gorm:"primaryKey:column:address;type:varchar(255)" json:"address"`
	AccountID  *uuid.UUID `gorm:"column:account_id;type:uuid"`
	IsVerified bool       `gorm:"column:is_verified;default:0" json:"is_verified"`
	VerifiedAt *time.Time `gorm:"column:verified_at;type:timestamp"`
	CreatedAt  time.Time  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}

func (e *Email) TableName() string {
	return "account_email"
}
