package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Role domain sentinel errors.
var (
	ErrRoleNameRequired       = errors.New("role name is required")
	ErrRoleNameTooLong        = errors.New("role name must not exceed 255 characters")
	ErrRoleDescriptionTooLong = errors.New("role description must not exceed 1024 characters")
	ErrRoleAlreadyDeleted     = errors.New("role is already deleted")
)

// Role is the role domain model.
type Role struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Permissions []string       `json:"permissions"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   *time.Time     `json:"deleted_at,omitempty"`
}

// NewRole creates a new role.
// Returns an error if name is empty or exceeds 255 characters.
func NewRole(name string, description *string) (*Role, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrRoleNameRequired
	}
	if len(name) > 255 {
		return nil, ErrRoleNameTooLong
	}
	if description != nil && len(*description) > 1024 {
		return nil, ErrRoleDescriptionTooLong
	}
	return &Role{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		Permissions: make([]string, 0),
		Metadata:    make(map[string]any),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

// IsDeleted reports whether the role has been soft-deleted.
func (r *Role) IsDeleted() bool {
	if r == nil {
		return false
	}
	return r.DeletedAt != nil
}

// SoftDelete soft-deletes the role.
func (r *Role) SoftDelete() error {
	if r == nil {
		return ErrRoleAlreadyDeleted
	}
	if r.IsDeleted() {
		return ErrRoleAlreadyDeleted
	}
	now := time.Now()
	r.DeletedAt = &now
	r.UpdatedAt = now
	return nil
}

// AddPermission adds a permission to the role.
// Empty or whitespace-only permissions are silently ignored.
func (r *Role) AddPermission(permission string) {
	if r == nil {
		return
	}
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return
	}
	// check if already present
	for _, p := range r.Permissions {
		if p == permission {
			return
		}
	}
	r.Permissions = append(r.Permissions, permission)
	r.UpdatedAt = time.Now()
}

// RemovePermission removes a permission from the role.
func (r *Role) RemovePermission(permission string) {
	if r == nil {
		return
	}
	permission = strings.TrimSpace(permission)
	for i, p := range r.Permissions {
		if p == permission {
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			r.UpdatedAt = time.Now()
			return
		}
	}
}

// HasPermission reports whether the role has the given permission.
func (r *Role) HasPermission(permission string) bool {
	if r == nil {
		return false
	}
	permission = strings.TrimSpace(permission)
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
