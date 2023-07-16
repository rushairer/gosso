package authorization

import (
	"context"
	"database/sql"
	"time"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (r *UserRepository) CreateUser(ctx context.Context, user User) (savedUser User, err error) {
	sqlString := `
		insert into users
			(connected_account_id, name, email, phone)
		values
			(?, ?, ?, ?)
		returning id, connected_account_id, name, email, phone, created_at, updated_at
	`

	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(
		ctx,
		user.ConnectedAccountId,
		user.Name,
		user.Email,
		user.Phone,
	)

	err = row.Scan(
		&savedUser.Id,
		&savedUser.ConnectedAccountId,
		&savedUser.Name,
		&savedUser.Email,
		&savedUser.Phone,
		&savedUser.CreatedAt,
		&savedUser.UpdatedAt,
	)

	return
}

func (r *UserRepository) DeleteUser(ctx context.Context, user User) (err error) {
	sqlString := `
		delete from users where name = ?
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, user.Name)

	return
}

func (r *UserRepository) SoftDeleteUser(ctx context.Context, user User) (err error) {
	sqlString := `
		update users set deleted_at = ? where id = ?
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, time.Now(), user.Id)

	return
}

func (r *UserRepository) GetUser(ctx context.Context, name string) (user User, err error) {
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
		return
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, name)
	err = row.Scan(
		&user.Id,
		&user.ConnectedAccountId,
		&user.Name,
		&user.Email,
		&user.Phone,
		&user.VerifiedAt,
		&user.DeletedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	return
}
