package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
	dbPkg "github.com/rushairer/gosso/internal/db"
)

type roleRepositoryImpl struct {
	db *sql.DB
}

const roleByIDQuery = `
	SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
	FROM roles
	WHERE id = $1 AND deleted_at IS NULL
	LIMIT 1
`

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

// UpdateRole updates a role with optimistic locking on updated_at.
func (r *roleRepositoryImpl) UpdateRole(ctx context.Context, tx *sql.Tx, role *domain.Role) error {
	query := `
		UPDATE roles
		SET name = $1, description = $2, permissions = $3, metadata = $4, updated_at = $5
		WHERE id = $6 AND deleted_at IS NULL AND updated_at = $7
	`

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}

	metadataJSON, err := json.Marshal(role.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	// Save expected value for optimistic locking
	expectedUpdatedAt := role.UpdatedAt
	newUpdatedAt := time.Now()

	result, err := tx.ExecContext(ctx, query,
		role.Name,
		role.Description,
		permissionsJSON,
		metadataJSON,
		newUpdatedAt,
		role.ID,
		expectedUpdatedAt,
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

	role.UpdatedAt = newUpdatedAt
	return nil
}

// FindByID finds a role by ID
func (r *roleRepositoryImpl) FindByID(ctx context.Context, roleID string) (*domain.Role, error) {
	return findRoleByID(ctx, r.db.QueryRowContext, roleID)
}

// FindByIDTx finds a role by ID within a transaction
func (r *roleRepositoryImpl) FindByIDTx(ctx context.Context, tx *sql.Tx, roleID string) (*domain.Role, error) {
	return findRoleByID(ctx, tx.QueryRowContext, roleID)
}

// findRoleByID is the shared implementation for both transactional and non-transactional variants.
func findRoleByID(ctx context.Context, queryRow func(context.Context, string, ...any) *sql.Row, roleID string) (*domain.Role, error) {
	role, err := scanRole(queryRow(ctx, roleByIDQuery, roleID))

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

// FindAll finds all roles with pagination.
func (r *roleRepositoryImpl) FindAll(ctx context.Context, page, pageSize int) ([]*domain.Role, int, error) {
	_, pageSize, offset := clampPagination(page, pageSize)

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE deleted_at IS NULL`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count roles: %w", err)
	}
	if total == 0 {
		return []*domain.Role{}, 0, nil
	}

	query := `
		SELECT id, name, description, permissions, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE deleted_at IS NULL
		ORDER BY name
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	roles, err := scanRoles(rows)
	if err != nil {
		return nil, 0, err
	}

	return roles, total, nil
}

// SoftDeleteRoleByID soft deletes a role
func (r *roleRepositoryImpl) SoftDeleteRoleByID(ctx context.Context, tx *sql.Tx, roleID string, deletedAt time.Time) error {
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
func (r *roleRepositoryImpl) AssignRoleToAccount(ctx context.Context, tx *sql.Tx, accountID, roleID string, createdAt time.Time) error {
	query := `
		INSERT INTO account_roles (account_id, role_id, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (account_id, role_id) WHERE deleted_at IS NULL DO NOTHING
	`

	_, err := tx.ExecContext(ctx, query, accountID, roleID, createdAt)
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
		return fmt.Errorf("%w: account=%s role=%s", ErrRoleAssignmentNotFound, accountID, roleID)
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

// FindRolesByAccountIDs returns all active role assignments for a page of
// accounts in one query. It is intentionally a package function rather than a
// RoleRepository interface method so existing domain consumers do not need a
// broader interface merely for the admin list projection.
func FindRolesByAccountIDs(ctx context.Context, db *sql.DB, accountIDs []string) (map[string][]*domain.Role, error) {
	result := make(map[string][]*domain.Role, len(accountIDs))
	if len(accountIDs) == 0 {
		return result, nil
	}

	placeholders := make([]string, len(accountIDs))
	args := make([]any, len(accountIDs))
	for i, accountID := range accountIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = accountID
		result[accountID] = make([]*domain.Role, 0)
	}

	query := `
		SELECT ar.account_id, r.id, r.name, r.description, r.permissions, r.metadata,
		       r.created_at, r.updated_at, r.deleted_at
		FROM account_roles ar
		INNER JOIN roles r ON r.id = ar.role_id
		WHERE ar.account_id IN (` + strings.Join(placeholders, ",") + `)
		  AND ar.deleted_at IS NULL AND r.deleted_at IS NULL
		ORDER BY ar.account_id, r.name`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query roles for account page: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var accountID string
		role := &domain.Role{}
		var permissionsJSON, metadataJSON []byte
		if err := rows.Scan(
			&accountID,
			&role.ID,
			&role.Name,
			&role.Description,
			&permissionsJSON,
			&metadataJSON,
			&role.CreatedAt,
			&role.UpdatedAt,
			&role.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan account role projection: %w", err)
		}
		role.Permissions = make([]string, 0)
		if err := dbPkg.UnmarshalJSONField(permissionsJSON, &role.Permissions, "permissions"); err != nil {
			return nil, err
		}
		role.Metadata = make(map[string]any)
		if err := dbPkg.UnmarshalJSONField(metadataJSON, &role.Metadata, "metadata"); err != nil {
			return nil, err
		}
		result[accountID] = append(result[accountID], role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account role projection: %w", err)
	}
	return result, nil
}

// SoftDeleteRolesByAccountID soft deletes all role associations for an account.
// Returns nil even if zero rows are affected (idempotent for bulk delete).
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
