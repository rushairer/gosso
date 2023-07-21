package authentication

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/markbates/goth"
)

type User struct {
	Id         string         `json:"-" db:"id"`
	Name       string         `json:"name" db:"name"`
	Email      sql.NullString `json:"-" db:"email,omitempty"`
	Phone      sql.NullString `json:"-" db:"phone,omitempty"`
	VerifiedAt sql.NullTime   `json:"-" db:"verified_at,omitempty"`
	DeletedAt  sql.NullTime   `json:"-" db:"deleted_at,omitempty"`
	CreatedAt  time.Time      `json:"-" db:"created_at"`
	UpdatedAt  time.Time      `json:"-" db:"updated_at"`
	UserDetail *UserDetail    `json:"user_detail"`
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

type ConnectedAccount struct {
	Id             int64          `json:"-" db:"id"`
	UserId         string         `json:"-" db:"user_id"`
	Provider       string         `json:"provider" db:"provider"`
	ProviderUserId string         `json:"provider_user_id" db:"provider_user_id"`
	Name           string         `json:"name" db:"name"`
	Email          string         `json:"email" db:"email"`
	Phone          string         `json:"phone" db:"phone"`
	Location       string         `json:"location" db:"location"`
	Nickname       string         `json:"nickname" db:"nickname"`
	Description    string         `json:"description" db:"description"`
	AvatarUrl      string         `json:"avatar_url" db:"avatar_url"`
	AccessToken    string         `json:"access_token" db:"access_token"`
	AccessSecret   string         `json:"access_secret" db:"access_secret"`
	RefreshToken   string         `json:"refresh_token" db:"refresh_token"`
	IdToken        string         `json:"id_token" db:"id_token"`
	RawData        sql.NullString `json:"raw_data" db:"raw_data,omitempty"`
	ExpiresAt      sql.NullTime   `json:"expires_at" db:"expires_at,omitempty"`
	CreatedAt      time.Time      `json:"-" db:"created_at"`
	UpdatedAt      time.Time      `json:"-" db:"updated_at"`
}

func NewConnectedAccountFromGothUser(gothUser goth.User) (ConnectedAccount, error) {
	if len(gothUser.Provider) == 0 {
		return ConnectedAccount{}, errors.New("invalid Provider of goth.User")
	}
	if len(gothUser.UserID) == 0 {
		return ConnectedAccount{}, errors.New("invalid UserID of goth.User")
	}
	if len(gothUser.Name) == 0 {
		return ConnectedAccount{}, errors.New("invalid Name of goth.User")
	}

	rawDataBytes, err := json.Marshal(gothUser.RawData)
	if err != nil {
		rawDataBytes = nil
	}

	rawData := sql.NullString{
		String: string(rawDataBytes),
		Valid:  len(rawDataBytes) > 0,
	}

	nickName := gothUser.NickName
	if len(nickName) == 0 {
		nickName = fmt.Sprintf("%s %s", gothUser.FirstName, gothUser.LastName)
	}

	return ConnectedAccount{
		Provider:       gothUser.Provider,
		ProviderUserId: gothUser.UserID,
		Name:           gothUser.Name,
		Email:          gothUser.Email,
		Location:       gothUser.Location,
		Nickname:       nickName,
		Description:    gothUser.Description,
		AvatarUrl:      gothUser.AvatarURL,
		AccessToken:    gothUser.AccessToken,
		AccessSecret:   gothUser.AccessTokenSecret,
		RefreshToken:   gothUser.RefreshToken,
		IdToken:        gothUser.IDToken,
		RawData:        rawData,
		ExpiresAt:      sql.NullTime{Time: gothUser.ExpiresAt, Valid: gothUser.ExpiresAt.After(time.Now())},
	}, nil
}
