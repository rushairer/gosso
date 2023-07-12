package authorization

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidUser       = errors.New("invalid user")
	ErrInvalidUserId     = errors.New("invalid user id")
	ErrInvalidUserName   = errors.New("invalid user name")
	ErrInvalidUserDetail = errors.New("invalid user detail")
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (r *UserRepository) FindUserByName(name string) (*User, error) {
	user := &User{}

	sqlString := `
		select
			id,
			connected_account_id,
			name,
			email,
			phone,
			verified_at,
			deleted_at,
			created_at,
			updated_at
		from
			users
		where
			name = ?
	`

	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(name)

	if err := row.Scan(
		&user.Id,
		&user.ConnectedAccountId,
		&user.Name,
		&user.Email,
		&user.Phone,
		&user.VerifiedAt,
		&user.DeletedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) SaveUser(user *User) error {
	if user == nil {
		return ErrInvalidUser
	}

	if len(user.Name) == 0 {
		return ErrInvalidUserName
	}
	now := time.Now()
	if len(user.Id) == 0 {
		user.Id = uuid.NewString()
		user.CreatedAt = now
	}
	user.UpdatedAt = now

	sqlString := `
		replace into users
			(id, connected_account_id, name, email, phone, created_at, updated_at)
		values
			(?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return err
	}
	defer stmt.Close()

	if _, err = stmt.Exec(
		user.Id,
		user.ConnectedAccountId,
		user.Name,
		user.Email,
		user.Phone,
		user.CreatedAt,
		user.UpdatedAt,
	); err != nil {
		return err
	}

	return nil
}

func (r *UserRepository) DeleteUser(user *User, softDelete bool) error {
	if user == nil {
		return ErrInvalidUser
	}

	if len(user.Id) == 0 {
		return ErrInvalidUserId
	}
	now := time.Now()
	var sqlString string

	user.DeletedAt = sql.NullTime{Time: now, Valid: true}

	if softDelete {
		sqlString = `
			update
				users
			set deleted_at = ?
			where
				id = ?
		`
	} else {
		sqlString = `
			delete from users where deleted_at <> ? and id = ?
		`
	}

	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return err
	}
	defer stmt.Close()

	if _, err = stmt.Exec(
		user.DeletedAt,
		user.Id,
	); err != nil {
		return err
	}

	return nil
}
