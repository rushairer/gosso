package account

import (
	"time"

	"github.com/google/uuid"
)

type AccountType int8

const (
	AccountTypeLocal AccountType = iota
	AccountTypePhone
	AccountTypeEmail
	AccountTypeSocial
)

func (a AccountType) String() string {
	return []string{"local", "phone", "email", "social"}[a]
}

func (a AccountType) Int() int8 {
	return int8(a)
}

type AccountStatus int8

const (
	AccountStatusNormal AccountStatus = iota
	AccountStatusDisabled
)

func (a AccountStatus) String() string {
	return []string{"normal", "disabled"}[a]
}

func (a AccountStatus) Int() int8 {
	return int8(a)
}

type Account struct {
	ID            uuid.UUID     `gorm:"primaryKey;type:char(36)" json:"id"`
	Nickname      string        `gorm:"column:nickname;type:varchar(64)" json:"nickname"`
	Type          AccountType   `gorm:"column:type;default:0" json:"type"`
	Status        AccountStatus `gorm:"column:status;default:0" json:"status"`
	CreatedAt     time.Time     `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt     time.Time     `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt     *time.Time    `gorm:"column:deleted_at;type:timestamp"`
	IsSoftDeleted bool          `gorm:"column:is_soft_deleted;default:0"`
}
