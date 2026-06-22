package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/account/domain"
	dbPkg "github.com/rushairer/gosso/internal/db"
)

func newTestRole() *domain.Role {
	desc := "Administrator"
	return &domain.Role{
		ID:          "role-001",
		Name:        "admin",
		Description: &desc,
		Permissions: []string{"read", "write", "delete"},
		Metadata:    map[string]any{"level": 1},
		CreatedAt:   time.Now().Add(-1 * time.Hour),
		UpdatedAt:   time.Now().Add(-1 * time.Hour),
	}
}

func roleColumns() []string {
	return []string{"id", "name", "description", "permissions", "metadata", "created_at", "updated_at", "deleted_at"}
}

func roleRowValues(role *domain.Role) []driver.Value {
	permsJSON, _ := json.Marshal(role.Permissions)
	metaJSON, _ := json.Marshal(role.Metadata)
	desc := ""
	if role.Description != nil {
		desc = *role.Description
	}
	return []driver.Value{role.ID, role.Name, desc, string(permsJSON), string(metaJSON), role.CreatedAt, role.UpdatedAt, nil}
}

func TestNewRoleRepository(t *testing.T) {
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	repo := NewRoleRepository(sqlDB)
	assert.NotNil(t, repo)
}

func TestRoleRepo_FindByID_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	role := newTestRole()
	rows := sqlmock.NewRows(roleColumns()).AddRow(roleRowValues(role)...)
	mock.ExpectQuery("SELECT (.+) FROM roles").WithArgs("role-001").WillReturnRows(rows)

	repo := NewRoleRepository(sqlDB)
	result, err := repo.FindByID(context.Background(), "role-001")

	require.NoError(t, err)
	assert.Equal(t, role.ID, result.ID)
	assert.Equal(t, role.Name, result.Name)
	assert.Equal(t, role.Description, result.Description)
	assert.Equal(t, role.Permissions, result.Permissions)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_FindByID_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery("SELECT (.+) FROM roles").WithArgs("nonexistent").WillReturnError(sql.ErrNoRows)

	repo := NewRoleRepository(sqlDB)
	result, err := repo.FindByID(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "role not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_FindByName_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	role := newTestRole()
	rows := sqlmock.NewRows(roleColumns()).AddRow(roleRowValues(role)...)
	mock.ExpectQuery("SELECT (.+) FROM roles").WithArgs("admin").WillReturnRows(rows)

	repo := NewRoleRepository(sqlDB)
	result, err := repo.FindByName(context.Background(), "admin")

	require.NoError(t, err)
	assert.Equal(t, "admin", result.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_FindByName_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery("SELECT (.+) FROM roles").WithArgs("nonexistent").WillReturnError(sql.ErrNoRows)

	repo := NewRoleRepository(sqlDB)
	result, err := repo.FindByName(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "role not found")
	assert.True(t, errors.Is(err, ErrRoleNotFound))
}

func TestRoleRepo_FindAll_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	role1 := newTestRole()
	role2Desc := "Regular user"
	role2 := &domain.Role{ID: "role-002", Name: "user", Description: &role2Desc, Permissions: []string{"read"}, Metadata: map[string]any{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}

	rows := sqlmock.NewRows(roleColumns()).
		AddRow(roleRowValues(role1)...).
		AddRow(roleRowValues(role2)...)
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery("SELECT (.+) FROM roles").WillReturnRows(rows)

	repo := NewRoleRepository(sqlDB)
	results, total, err := repo.FindAll(context.Background(), 1, 20)

	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 2, total)
	assert.Equal(t, "admin", results[0].Name)
	assert.Equal(t, "user", results[1].Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_FindAll_Empty(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	repo := NewRoleRepository(sqlDB)
	results, total, err := repo.FindAll(context.Background(), 1, 20)

	require.NoError(t, err)
	assert.Len(t, results, 0)
	assert.Equal(t, 0, total)
}

func TestRoleRepo_FindRolesByAccountID_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	role := newTestRole()
	rows := sqlmock.NewRows(roleColumns()).AddRow(roleRowValues(role)...)
	mock.ExpectQuery("SELECT (.+) FROM roles r").WithArgs("account-001").WillReturnRows(rows)

	repo := NewRoleRepository(sqlDB)
	results, err := repo.FindRolesByAccountID(context.Background(), "account-001")

	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "admin", results[0].Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_FindRolesByAccountID_Empty(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	rows := sqlmock.NewRows(roleColumns())
	mock.ExpectQuery("SELECT (.+) FROM roles r").WithArgs("account-001").WillReturnRows(rows)

	repo := NewRoleRepository(sqlDB)
	results, err := repo.FindRolesByAccountID(context.Background(), "account-001")

	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestRoleRepo_AssignRoleToAccount(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO account_roles").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	repo := NewRoleRepository(sqlDB)

	err = dbPkg.RunInTransaction(context.Background(), sqlDB, func(tx *sql.Tx) error {
		return repo.AssignRoleToAccount(context.Background(), tx, "account-001", "role-001", time.Now())
	})

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_RemoveRoleFromAccount_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	repo := NewRoleRepository(sqlDB)

	err = dbPkg.RunInTransaction(context.Background(), sqlDB, func(tx *sql.Tx) error {
		return repo.RemoveRoleFromAccount(context.Background(), tx, "account-001", "role-001", time.Now())
	})

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_RemoveRoleFromAccount_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	repo := NewRoleRepository(sqlDB)

	err = dbPkg.RunInTransaction(context.Background(), sqlDB, func(tx *sql.Tx) error {
		return repo.RemoveRoleFromAccount(context.Background(), tx, "account-001", "role-999", time.Now())
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment not found")
	assert.True(t, errors.Is(err, ErrRoleAssignmentNotFound))
}

func TestRoleRepo_SoftDeleteRolesByAccountID(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE account_roles SET deleted_at").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	repo := NewRoleRepository(sqlDB)

	err = dbPkg.RunInTransaction(context.Background(), sqlDB, func(tx *sql.Tx) error {
		return repo.SoftDeleteRolesByAccountID(context.Background(), tx, "account-001", time.Now())
	})

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// CreateRole
// ──────────────────────────────────────────────

func TestRoleRepo_CreateRole_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	tx, _ := sqlDB.Begin()

	role := newTestRole()
	mock.ExpectExec("INSERT INTO roles").
		WithArgs(role.ID, role.Name, role.Description,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			role.CreatedAt, role.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRoleRepository(sqlDB)
	err = repo.CreateRole(context.Background(), tx, role)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// UpdateRole
// ──────────────────────────────────────────────

func TestRoleRepo_UpdateRole_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	tx, _ := sqlDB.Begin()

	role := newTestRole()
	mock.ExpectExec("UPDATE roles").
		WithArgs(role.Name, role.Description,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), role.ID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRoleRepository(sqlDB)
	err = repo.UpdateRole(context.Background(), tx, role)

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_UpdateRole_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	tx, _ := sqlDB.Begin()

	role := newTestRole()
	mock.ExpectExec("UPDATE roles").
		WithArgs(role.Name, role.Description,
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), role.ID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewRoleRepository(sqlDB)
	err = repo.UpdateRole(context.Background(), tx, role)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role not found")
	assert.True(t, errors.Is(err, ErrRoleNotFound))
}

// ──────────────────────────────────────────────
// SoftDeleteRoleByID
// ──────────────────────────────────────────────

func TestRoleRepo_SoftDeleteRoleByID_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	tx, _ := sqlDB.Begin()

	mock.ExpectExec("UPDATE roles").
		WithArgs(sqlmock.AnyArg(), "role-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRoleRepository(sqlDB)
	err = repo.SoftDeleteRoleByID(context.Background(), tx, "role-001", time.Now())

	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoleRepo_SoftDeleteRoleByID_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	tx, _ := sqlDB.Begin()

	mock.ExpectExec("UPDATE roles").
		WithArgs(sqlmock.AnyArg(), "nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewRoleRepository(sqlDB)
	err = repo.SoftDeleteRoleByID(context.Background(), tx, "nonexistent", time.Now())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role not found")
	assert.True(t, errors.Is(err, ErrRoleNotFound))
}
