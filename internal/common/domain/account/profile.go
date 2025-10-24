package account

import (
	"time"

	"github.com/google/uuid"
)

type ProfileGender int8

const (
	ProfileGenderUnknown ProfileGender = iota
	ProfileGenderMale
	ProfileGenderFemale
)

type Profile struct {
	AccountID uuid.UUID     `gorm:"primaryKey;column:account_id;type:char(36)"`
	Avatar    string        `gorm:"column:avatar;type:varchar(255)" json:"avatar"`
	Gender    ProfileGender `gorm:"column:gender;default:0" json:"gender"`
	Age       int           `gorm:"column:age" json:"age"`
	Address   string        `gorm:"column:address;type:varchar(500)" json:"address"`
	CreatedAt time.Time     `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time     `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}

func (p *Profile) TableName() string {
	return "account_profile"
}
