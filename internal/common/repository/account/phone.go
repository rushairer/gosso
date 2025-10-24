package account

import (
	"context"
	"gosso/internal/common/domain/account"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type PhoneRepository interface {
	FindOrCreate(
		ctx context.Context,
		number string,
	) (
		phone account.Phone,
		created bool,
		err error,
	)
}

type PhoneMySQLRepository struct {
	db *gorm.DB
}

func NewPhoneMySQLRepository(db *gorm.DB) *PhoneMySQLRepository {
	return &PhoneMySQLRepository{
		db: db,
	}
}

func (r *PhoneMySQLRepository) FindOrCreate(
	ctx context.Context,
	number string,
) (
	phone account.Phone,
	created bool,
	err error,
) {
	phone.Number = number

	if err = gorm.G[account.Phone](
		r.db,
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "number"}}, // 指定冲突检测列
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		},
		clause.Returning{},
	).Create(ctx, &phone); err != nil {
		return
	}
	created = phone.CreatedAt.Equal(phone.UpdatedAt)
	return
}
