package authorization

import (
	"database/sql"
	"time"
)

type User struct {
	Id                 string         `json:"-" db:"id"`
	ConnectedAccountId sql.NullInt64  `json:"-" db:"connected_account_id,omitempty"`
	Name               string         `json:"name" db:"name"`
	Email              sql.NullString `json:"-" db:"email,omitempty"`
	Phone              sql.NullString `json:"-" db:"phone,omitempty"`
	VerifiedAt         sql.NullTime   `json:"-" db:"verified_at,omitempty"`
	DeletedAt          sql.NullTime   `json:"-" db:"deleted_at,omitempty"`
	CreatedAt          time.Time      `json:"-" db:"created_at"`
	UpdatedAt          time.Time      `json:"-" db:"updated_at"`
	UserDetail         *UserDetail    `json:"user_detail"`
}

func (u *User) IsDeleted() bool {
	return u.DeletedAt.Valid
}

func (u *User) IsVerified() bool {
	return u.VerifiedAt.Valid
}

type UserDetail struct {
	Id          string         `json:"-" db:"id"`
	Nickname    string         `json:"nickname" db:"nickname"`
	AvatarUrl   sql.NullString `json:"avatar_url" db:"avatar_url"`
	Description string         `json:"description" db:"description"`
	Location    sql.NullString `json:"location" db:"location"`
	CreatedAt   time.Time      `json:"-" db:"created_at"`
	UpdatedAt   time.Time      `json:"-" db:"updated_at"`
}
