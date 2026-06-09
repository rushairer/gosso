package db

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

func TestIsUniqueViolation_Nil(t *testing.T) {
	assert.False(t, IsUniqueViolation(nil))
}

func TestIsUniqueViolation_PgError(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505"}
	assert.True(t, IsUniqueViolation(pgErr))
}

func TestIsUniqueViolation_PgErrorOtherCode(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23503"}
	assert.False(t, IsUniqueViolation(pgErr))
}

func TestIsUniqueViolation_RegularError(t *testing.T) {
	err := errors.New("something else")
	assert.False(t, IsUniqueViolation(err))
}
