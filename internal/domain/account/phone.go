package account

import (
	"time"

	"github.com/google/uuid"
)

type Phone struct {
	Number    string     `gorm:"primaryKey:column:number;type:varchar(64)" json:"number"`
	AccountID *uuid.UUID `gorm:"column:account_id;type:uuid"`
	CreatedAt time.Time  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

func (p *Phone) TableName() string {
	return "account_phone"
}
