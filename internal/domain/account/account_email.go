package account

import (
	"time"

	"github.com/google/uuid"
)

type AccountEmail struct {
	Email     string     `gorm:"primaryKey:column:email;type:varchar(255)" json:"email"`
	AccountID *uuid.UUID `gorm:"column:account_id;type:uuid"`
	CreatedAt time.Time  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

func (a AccountEmail) TableName() string {
	return "account_email"
}
