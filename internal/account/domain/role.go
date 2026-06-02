package domain

import (
	"time"

	"github.com/google/uuid"
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
func NewRole(name string, description *string) *Role {
	return &Role{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		Permissions: make([]string, 0),
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// IsDeleted reports whether the role has been soft-deleted.
func (r *Role) IsDeleted() bool {
	return r.DeletedAt != nil
}

// SoftDelete soft-deletes the role.
func (r *Role) SoftDelete() {
	now := time.Now()
	r.DeletedAt = &now
	r.UpdatedAt = now
}

// AddPermission adds a permission to the role.
func (r *Role) AddPermission(permission string) {
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
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
