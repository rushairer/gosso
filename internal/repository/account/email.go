package account

import (
	"context"

	"gosso/internal/domain/account"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EmailRepository interface {
	FindOrCreate(
		ctx context.Context,
		address string,
	) (
		email account.Email,
		created bool,
		err error,
	)
}

type EmailMySQLRepository struct {
	db *gorm.DB
}

func NewEmailMySQLRepository(db *gorm.DB) *EmailMySQLRepository {
	return &EmailMySQLRepository{db: db}
}

func (r *EmailMySQLRepository) FindOrCreate(
	ctx context.Context,
	address string,
) (
	email account.Email,
	created bool,
	err error,
) {
	email.Address = address
	uuidString, _ := uuid.NewUUID()
	email.AccountID = &uuidString

	if err = gorm.G[account.Email](
		r.db,
		clause.OnConflict{
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		},
		clause.Returning{},
	).Create(ctx, &email); err != nil {
		return
	}
	created = email.CreatedAt.Equal(email.UpdatedAt)
	return
}
