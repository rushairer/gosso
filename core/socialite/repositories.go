package socialite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrInvalidSocialiteProvider = errors.New("invalid socialite provider")
)

type SocialiteRepository struct {
	db *sql.DB
}

func NewSocialiteRepository(db *sql.DB) *SocialiteRepository {
	return &SocialiteRepository{
		db: db,
	}
}

func (r *SocialiteRepository) CreateSocialiteProvider(
	ctx context.Context,
	socialiteProvider SocialiteProvider,
) (
	savedSocialiteProvider SocialiteProvider,
	err error,
) {
	sqlString := `
		insert into socialite_providers
			(name, provider, status, config)
		values
			(?, ?, ?, ?)
		returning id, name, provider, status, config, created_at, updated_at
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(
		ctx,
		socialiteProvider.Name,
		socialiteProvider.Provider,
		socialiteProvider.Status,
		socialiteProvider.Config,
	)

	err = row.Scan(
		&savedSocialiteProvider.Id,
		&savedSocialiteProvider.Name,
		&savedSocialiteProvider.Provider,
		&savedSocialiteProvider.Status,
		&savedSocialiteProvider.Config,
		&savedSocialiteProvider.CreatedAt,
		&savedSocialiteProvider.UpdatedAt,
	)

	return
}

func (r *SocialiteRepository) DeleteSocialiteProvider(
	ctx context.Context,
	socialiteProvider SocialiteProvider,
) (err error) {
	sqlString := `
		delete from socialite_providers where id = ?
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, socialiteProvider.Id)

	return
}

func (r *SocialiteRepository) SoftDeleteSocialiteProvider(
	ctx context.Context,
	socialiteProvider SocialiteProvider,
) (err error) {
	sqlString := `
		update socialite_providers set deleted_at = ? where id = ?
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, time.Now(), socialiteProvider.Id)

	return
}

func (r *SocialiteRepository) GetSocialiteProvider(
	ctx context.Context,
	id int64,
) (
	socialiteProvider SocialiteProvider,
	err error,
) {
	sqlString := `
		select
			id,
			name,
			provider,
			status,
			config,
			created_at,
			updated_at
		from
			socialite_providers
		where
			id = ?
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, id)
	err = row.Scan(
		&socialiteProvider.Id,
		&socialiteProvider.Name,
		&socialiteProvider.Provider,
		&socialiteProvider.Status,
		&socialiteProvider.Config,
		&socialiteProvider.CreatedAt,
		&socialiteProvider.UpdatedAt,
	)

	return
}

func (r *SocialiteRepository) GetSocialiteProviderList(ctx context.Context, status SocialiteProviderStatus) (list []SocialiteProvider, err error) {
	sqlString := `
		select
			id,
			name,
			provider,
			status,
			config,
			created_at,
			updated_at
		from
			socialite_providers
		where
			status = ?
	`
	stmt, err := r.db.Prepare(sqlString)
	if err != nil {
		return
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, status)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var socialiteProvider SocialiteProvider
		if err = rows.Scan(
			&socialiteProvider.Id,
			&socialiteProvider.Name,
			&socialiteProvider.Provider,
			&socialiteProvider.Status,
			&socialiteProvider.Config,
			&socialiteProvider.CreatedAt,
			&socialiteProvider.UpdatedAt,
		); err != nil {
			return
		}
		list = append(list, socialiteProvider)
	}
	if err = rows.Close(); err != nil {
		return
	}
	if err = rows.Err(); err != nil {
		return
	}

	return
}
