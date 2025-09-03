package repository

import "context"

type AccountRepository struct {
}

func NewAccountRepository() *AccountRepository {
	return &AccountRepository{}
}

func (c *AccountRepository) Get(ctx context.Context) (result string, err error) {
	return
}