package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
)

// RoleRepository 角色仓储接口
type RoleRepository interface {
	// CreateRole 创建角色（需要事务）
	CreateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error

	// UpdateRole 更新角色（需要事务）
	UpdateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error

	// FindByID 根据 ID 查找角色
	FindByID(ctx context.Context, roleID string) (*domain.Role, error)

	// FindByName 根据名称查找角色
	FindByName(ctx context.Context, name string) (*domain.Role, error)

	// FindAll 查找所有角色
	FindAll(ctx context.Context) ([]*domain.Role, error)

	// SoftDeleteByID 软删除角色（需要事务）
	SoftDeleteByID(ctx context.Context, tx *sql.Tx, roleID string, deletedAt time.Time) error

	// AssignRoleToAccount 为账号分配角色（需要事务）
	AssignRoleToAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string) error

	// RemoveRoleFromAccount 移除账号的角色（软删除，需要事务）
	RemoveRoleFromAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string, deletedAt time.Time) error

	// FindRolesByAccountID 查找账号的所有角色
	FindRolesByAccountID(ctx context.Context, accountID string) ([]*domain.Role, error)

	// SoftDeleteRolesByAccountID 软删除账号的所有角色关联（需要事务）
	SoftDeleteRolesByAccountID(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error
}

type roleRepositoryImpl struct {
	db *sql.DB
}

// NewRoleRepository 创建角色仓储
func NewRoleRepository(db *sql.DB) RoleRepository {
	return &roleRepositoryImpl{db: db}
}

// CreateRole 创建角色
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

// UpdateRole 更新角色
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
		return fmt.Errorf("role not found or already deleted: %s", role.ID)
	}

	return nil
}

// FindByID 根据 ID 查找角色
func (r *roleRepositoryImpl) FindByID(ctx context.Context, roleID string) (*domain.Role, error) {
	query := `
		SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE id = $1 AND deleted_at IS NULL
		LIMIT 1
	`

	role := &domain.Role{}
	var permissionsJSON, metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, roleID).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&metadataJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
		&role.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found: %s", roleID)
	}
	if err != nil {
		return nil, fmt.Errorf("query role: %w", err)
	}

	if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshal permissions: %w", err)
	}

	if err := json.Unmarshal(metadataJSON, &role.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return role, nil
}

// FindByName 根据名称查找角色
func (r *roleRepositoryImpl) FindByName(ctx context.Context, name string) (*domain.Role, error) {
	query := `
		SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE name = $1 AND deleted_at IS NULL
		LIMIT 1
	`

	role := &domain.Role{}
	var permissionsJSON, metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&metadataJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
		&role.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found with name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("query role: %w", err)
	}

	if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshal permissions: %w", err)
	}

	if err := json.Unmarshal(metadataJSON, &role.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return role, nil
}

// FindAll 查找所有角色
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
	defer rows.Close()

	var roles []*domain.Role
	for rows.Next() {
		role := &domain.Role{}
		var permissionsJSON, metadataJSON []byte

		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&permissionsJSON,
			&metadataJSON,
			&role.CreatedAt,
			&role.UpdatedAt,
			&role.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}

		if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
			return nil, fmt.Errorf("unmarshal permissions: %w", err)
		}

		if err := json.Unmarshal(metadataJSON, &role.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}

		roles = append(roles, role)
	}

	return roles, nil
}

// SoftDeleteByID 软删除角色
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
		return fmt.Errorf("role not found or already deleted: %s", roleID)
	}

	return nil
}

// AssignRoleToAccount 为账号分配角色
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

// RemoveRoleFromAccount 移除账号的角色（软删除）
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
		return fmt.Errorf("account-role association not found or already deleted")
	}

	return nil
}

// FindRolesByAccountID 查找账号的所有角色
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
	defer rows.Close()

	var roles []*domain.Role
	for rows.Next() {
		role := &domain.Role{}
		var permissionsJSON, metadataJSON []byte

		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&permissionsJSON,
			&metadataJSON,
			&role.CreatedAt,
			&role.UpdatedAt,
			&role.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}

		if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
			return nil, fmt.Errorf("unmarshal permissions: %w", err)
		}

		if err := json.Unmarshal(metadataJSON, &role.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}

		roles = append(roles, role)
	}

	return roles, nil
}

// SoftDeleteRolesByAccountID 软删除账号的所有角色关联
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
