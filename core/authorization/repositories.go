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
			(name, email, phone)
		values
			(?, ?, ?)
		returning id, name, email, phone, created_at, updated_at
	`

	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(
		ctx,
		user.Name,
		user.Email,
		user.Phone,
	)

	err = row.Scan(
		&savedUser.Id,
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

func (r *UserRepository) GetUserWithDetailById(ctx context.Context, id string) (user User, err error) {
	sqlString := `
		select
			id,
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
			id = ?
	`

	stmtUsers, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtUsers.Close()

	row := stmtUsers.QueryRowContext(ctx, id)
	err = row.Scan(
		&user.Id,
		&user.Name,
		&user.Email,
		&user.Phone,
		&user.VerifiedAt,
		&user.DeletedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	userDetail := UserDetail{}

	sqlString = `
		select
			id,
			nickname,
			avatar_url,
			description,
			location,
			created_at,
			updated_at
		from
			user_details
		where
			id = ?
	`
	stmtUserDetails, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtUserDetails.Close()

	row = stmtUserDetails.QueryRowContext(ctx, id)
	err = row.Scan(
		&userDetail.Id,
		&userDetail.Nickname,
		&userDetail.AvatarUrl,
		&userDetail.Description,
		&userDetail.Location,
		&userDetail.CreatedAt,
		&userDetail.UpdatedAt,
	)

	user.UserDetail = &userDetail
	return
}

func (r *UserRepository) GetConnectedAccount(
	ctx context.Context,
	provider string,
	providerUserId string,
) (connectedAccount ConnectedAccount, err error) {
	sqlString := `
		select
			id,
			user_id,
			provider,
			provider_user_id,
			name,
			email,
			phone,
			location,
			nickname,
			description,
			avatar_url,
			access_token,
			access_secret,
			refresh_token,
			id_token,
			raw_data,
			expires_at,
			created_at,
			updated_at
		from
			connected_accounts
		where
			provider = ?
			and provider_user_id = ?
	`

	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, provider, providerUserId)
	err = row.Scan(
		&connectedAccount.Id,
		&connectedAccount.UserId,
		&connectedAccount.Provider,
		&connectedAccount.ProviderUserId,
		&connectedAccount.Name,
		&connectedAccount.Email,
		&connectedAccount.Phone,
		&connectedAccount.Location,
		&connectedAccount.Nickname,
		&connectedAccount.Description,
		&connectedAccount.AvatarUrl,
		&connectedAccount.AccessToken,
		&connectedAccount.AccessSecret,
		&connectedAccount.RefreshToken,
		&connectedAccount.IdToken,
		&connectedAccount.RawData,
		&connectedAccount.ExpiresAt,
		&connectedAccount.CreatedAt,
		&connectedAccount.UpdatedAt,
	)

	return
}

// Create an account with ConnectedAccount, insert data into users, user_details and connected_accounts tables.
// Return the user id.
func (r *UserRepository) CreateAccountWithConnectedAccount(ctx context.Context, connectedAccount ConnectedAccount) (accountId string, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()

	sqlString := `
		insert into users
			(name, email, phone)
		values
			(?, ?, ?)
		returning id
	`
	stmtUsers, err := tx.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtUsers.Close()

	row := stmtUsers.QueryRowContext(
		ctx,
		connectedAccount.Name,
		connectedAccount.Email,
		connectedAccount.Phone,
	)

	err = row.Scan(&accountId)
	if err != nil {
		return
	}

	connectedAccount.UserId = accountId

	sqlString = `
		insert into user_details
			(id, nickname, avatar_url, description, location)
		values
			(?, ?, ?, ?, ?)
	`

	stmtUserDetails, err := tx.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtUserDetails.Close()

	_, err = stmtUserDetails.ExecContext(
		ctx,
		accountId,
		connectedAccount.Nickname,
		connectedAccount.AvatarUrl,
		connectedAccount.Description,
		connectedAccount.Location,
	)
	if err != nil {
		return
	}

	sqlString = `
		insert into connected_accounts
			(
				user_id,
				provider,
				provider_user_id,
				name,
				email,
				phone,
				location,
				nickname,
				description,
				avatar_url,
				access_token,
				access_secret,
				refresh_token,
				id_token,
				raw_data,
				expires_at
			)
		values
			(
				?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			)
	`

	stmtConnectedAccounts, err := tx.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtConnectedAccounts.Close()

	_, err = stmtConnectedAccounts.ExecContext(
		ctx,
		connectedAccount.UserId,
		connectedAccount.Provider,
		connectedAccount.ProviderUserId,
		connectedAccount.Name,
		connectedAccount.Email,
		connectedAccount.Phone,
		connectedAccount.Location,
		connectedAccount.Nickname,
		connectedAccount.Description,
		connectedAccount.AvatarUrl,
		connectedAccount.AccessToken,
		connectedAccount.AccessSecret,
		connectedAccount.RefreshToken,
		connectedAccount.IdToken,
		connectedAccount.RawData,
		connectedAccount.ExpiresAt,
	)
	if err != nil {
		return
	}

	if err = tx.Commit(); err != nil {
		return
	}

	return
}

// Delete an account with id.
func (r *UserRepository) DeleteAccount(ctx context.Context, accountId string) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()

	sqlString := `
		delete from users where id = ?
	`
	stmtUsers, err := tx.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtUsers.Close()

	_, err = stmtUsers.ExecContext(ctx, accountId)
	if err != nil {
		return
	}

	sqlString = `
		delete from user_details where id = ?
	`

	stmtUserDetails, err := tx.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtUserDetails.Close()

	_, err = stmtUserDetails.ExecContext(ctx, accountId)
	if err != nil {
		return
	}

	sqlString = `
		delete from connected_accounts where user_id = ?
	`

	stmtConnectedAccounts, err := tx.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmtConnectedAccounts.Close()

	_, err = stmtConnectedAccounts.ExecContext(ctx, accountId)
	if err != nil {
		return
	}

	if err = tx.Commit(); err != nil {
		return
	}

	return
}
