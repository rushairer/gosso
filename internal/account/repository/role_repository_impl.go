package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

type roleRepositoryImpl struct {
	db *sql.DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *sql.DB) RoleRepository {
	return &roleRepositoryImpl{db: db}
}

// CreateRole creates a role
func (r *roleRepositoryImpl) CreateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error {
	query := `
		INSERT INTO roles (id, name, description, permissions, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}

	metadataJSON, err := json.Marshal(role.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		role.ID,
		role.Name,
		role.Description,
		permissionsJSON,
		metadataJSON,
		role.CreatedAt,
		role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert role: %w", err)
	}

	return nil
}

// UpdateRole updates a role
func (r *roleRepositoryImpl) UpdateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error {
	query := `
		UPDATE roles
		SET name = $1, description = $2, permissions = $3, metadata = $4, updated_at = $5
		WHERE id = $6 AND deleted_at IS NULL
	`

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}

	metadataJSON, err := json.Marshal(role.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	result, err := tx.ExecContext(ctx, query,
		role.Name,
		role.Description,
		permissionsJSON,
		metadataJSON,
		role.UpdatedAt,
		role.ID,
	)
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, role.ID)
	}

	return nil
}

// FindByID finds a role by ID
func (r *roleRepositoryImpl) FindByID(ctx context.Context, roleID string) (*domain.Role, error) {
	query := `
		SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE id = $1 AND deleted_at IS NULL
		LIMIT 1
	`

	role, err := scanRole(r.db.QueryRowContext(ctx, query, roleID))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotFound, roleID)
	}
	if err != nil {
		return nil, fmt.Errorf("query role: %w", err)
	}

	return role, nil
}

// FindByName finds a role by name
func (r *roleRepositoryImpl) FindByName(ctx context.Context, name string) (*domain.Role, error) {
	query := `
		SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE name = $1 AND deleted_at IS NULL
		LIMIT 1
	`

	role, err := scanRole(r.db.QueryRowContext(ctx, query, name))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("query role: %w", err)
	}

	return role, nil
}

// FindAll finds all roles
func (r *roleRepositoryImpl) FindAll(ctx context.Context) ([]*domain.Role, error) {
	query := `
		SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE deleted_at IS NULL
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	roles, err := scanRoles(rows)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// SoftDeleteByID soft deletes a role
func (r *roleRepositoryImpl) SoftDeleteByID(ctx context.Context, tx *sql.Tx, roleID string, deletedAt time.Time) error {
	query := `
		UPDATE roles
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, roleID)
	if err != nil {
		return fmt.Errorf("soft delete role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, roleID)
	}

	return nil
}

// AssignRoleToAccount assigns a role to an account
func (r *roleRepositoryImpl) AssignRoleToAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string) error {
	query := `
		INSERT INTO account_roles (account_id, role_id, created_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (account_id, role_id) WHERE deleted_at IS NULL DO NOTHING
	`

	_, err := tx.ExecContext(ctx, query, accountID, roleID)
	if err != nil {
		return fmt.Errorf("assign role to account: %w", err)
	}

	return nil
}

// RemoveRoleFromAccount removes a role from an account (soft delete)
func (r *roleRepositoryImpl) RemoveRoleFromAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string, deletedAt time.Time) error {
	query := `
		UPDATE account_roles
		SET deleted_at = $1
		WHERE account_id = $2 AND role_id = $3 AND deleted_at IS NULL
	`

	result, err := tx.ExecContext(ctx, query, deletedAt, accountID, roleID)
	if err != nil {
		return fmt.Errorf("remove role from account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%w: account=%s role=%s", ErrRoleNotFound, accountID, roleID)
	}

	return nil
}

// FindRolesByAccountID finds all roles associated with an account ID
func (r *roleRepositoryImpl) FindRolesByAccountID(ctx context.Context, accountID string) ([]*domain.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.permissions, r.metadata, r.created_at, r.updated_at, r.deleted_at
		FROM roles r
		INNER JOIN account_roles ar ON r.id = ar.role_id
		WHERE ar.account_id = $1 AND ar.deleted_at IS NULL AND r.deleted_at IS NULL
		ORDER BY r.name
	`

	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("query account roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	roles, err := scanRoles(rows)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// SoftDeleteRolesByAccountID soft deletes all role associations for an account
func (r *roleRepositoryImpl) SoftDeleteRolesByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	query := `
		UPDATE account_roles
		SET deleted_at = $1
		WHERE account_id = $2 AND deleted_at IS NULL
	`

	_, err := tx.ExecContext(ctx, query, deletedAt, accountID)
	if err != nil {
		return fmt.Errorf("soft delete account roles: %w", err)
	}

	return nil
}
