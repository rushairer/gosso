package account

import (
	"context"

	"gosso/internal/domain/account"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AccountEmailRepository interface {
	FindOrCreate(
		ctx context.Context,
		email string,
	) (
		accountEmail account.AccountEmail,
		created bool,
		err error,
	)
}

type AccountEmailMySQLRepository struct {
	db *gorm.DB
}

func NewAccountEmailMySQLRepository(db *gorm.DB) *AccountEmailMySQLRepository {
	return &AccountEmailMySQLRepository{db: db}
}

func (r *AccountEmailMySQLRepository) FindOrCreate(
	ctx context.Context,
	email string,
) (
	accountEmail account.AccountEmail,
	created bool,
	err error,
) {
	accountEmail.Email = email
	uuidString, _ := uuid.NewUUID()
	accountEmail.AccountID = &uuidString

	if err = gorm.G[account.AccountEmail](
		r.db,
		clause.OnConflict{
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		},
		clause.Returning{},
	).Create(ctx, &accountEmail); err != nil {
		return
	}
	created = accountEmail.CreatedAt.Equal(accountEmail.UpdatedAt)
	return
}
