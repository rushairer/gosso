package account

import (
	"context"
	"gosso/internal/domain/account"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AccountPhoneRepository interface {
	FindOrCreate(
		ctx context.Context,
		phone string,
	) (
		accountPhone account.AccountPhone,
		created bool,
		err error,
	)
}

type AccountPhoneMySQLRepository struct {
	db *gorm.DB
}

func NewAccountPhoneMySQLRepository(db *gorm.DB) *AccountPhoneMySQLRepository {
	return &AccountPhoneMySQLRepository{
		db: db,
	}
}

func (r *AccountPhoneMySQLRepository) FindOrCreate(
	ctx context.Context,
	phone string,
) (
	accountPhone account.AccountPhone,
	created bool,
	err error,
) {
	accountPhone.Phone = phone

	if err = gorm.G[account.AccountPhone](
		r.db,
		clause.OnConflict{
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		},
		clause.Returning{},
	).Create(ctx, &accountPhone); err != nil {
		return
	}
	created = accountPhone.CreatedAt.Equal(accountPhone.UpdatedAt)
	return
}
