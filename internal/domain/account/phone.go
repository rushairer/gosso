package account

import (
	"time"

	"github.com/google/uuid"
)

type Phone struct {
	Number     string     `gorm:"primaryKey:column:number;type:varchar(64)" json:"number"`
	AccountID  *uuid.UUID `gorm:"column:account_id;type:char(36)"`
	IsVerified bool       `gorm:"column:is_verified;default:0" json:"is_verified"`
	VerifiedAt *time.Time `gorm:"column:verified_at;type:timestamp"`
	CreatedAt  time.Time  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}

func (p *Phone) TableName() string {
	return "account_phone"
}
