package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

// Sentinel errors for repository operations
var (
	ErrRoleNotFound = errors.New("role not found")
)

// RoleRepository defines the interface for role repository
type RoleRepository interface {
	// CreateRole creates a role (requires transaction)
	CreateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error

	// UpdateRole updates a role (requires transaction)
	UpdateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error

	// FindByID finds a role by ID
	FindByID(ctx context.Context, roleID string) (*domain.Role, error)

	// FindByIDTx finds a role by ID within a transaction
	FindByIDTx(ctx context.Context, tx *sql.Tx, roleID string) (*domain.Role, error)

	// FindByName finds a role by name
	FindByName(ctx context.Context, name string) (*domain.Role, error)

	// FindAll finds all roles with pagination. Returns roles and total count.
	FindAll(ctx context.Context, page, pageSize int) ([]*domain.Role, int, error)

	// SoftDeleteByID soft deletes a role by ID (requires transaction)
	SoftDeleteByID(ctx context.Context, tx *sql.Tx, roleID string, deletedAt time.Time) error

	// AssignRoleToAccount assigns a role to an account (requires transaction)
	AssignRoleToAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string) error

	// RemoveRoleFromAccount removes a role from an account (soft delete, requires transaction)
	RemoveRoleFromAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string, deletedAt time.Time) error

	// FindRolesByAccountID finds all roles associated with an account ID
	FindRolesByAccountID(ctx context.Context, accountID string) ([]*domain.Role, error)

	// SoftDeleteRolesByAccountID soft deletes all role associations for an account (requires transaction)
	SoftDeleteRolesByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
}
