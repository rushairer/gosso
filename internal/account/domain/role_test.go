package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ──────────────────────────────────────────────
// AddPermission
// ──────────────────────────────────────────────

func TestAddPermission_New(t *testing.T) {
	r := &Role{Permissions: []string{}}
	r.AddPermission("read")
	assert.Equal(t, []string{"read"}, r.Permissions)
}

func TestAddPermission_Duplicate(t *testing.T) {
	r := &Role{Permissions: []string{"read"}}
	r.AddPermission("read")
	assert.Equal(t, []string{"read"}, r.Permissions)
}

func TestAddPermission_Multiple(t *testing.T) {
	r := &Role{Permissions: []string{}}
	r.AddPermission("read")
	r.AddPermission("write")
	r.AddPermission("delete")
	assert.Equal(t, []string{"read", "write", "delete"}, r.Permissions)
}

// ──────────────────────────────────────────────
// RemovePermission
// ──────────────────────────────────────────────

func TestRemovePermission_Exists(t *testing.T) {
	r := &Role{Permissions: []string{"read", "write", "delete"}}
	r.RemovePermission("write")
	assert.Equal(t, []string{"read", "delete"}, r.Permissions)
}

func TestRemovePermission_NotExists(t *testing.T) {
	r := &Role{Permissions: []string{"read", "write"}}
	r.RemovePermission("admin")
	assert.Equal(t, []string{"read", "write"}, r.Permissions)
}

func TestRemovePermission_Last(t *testing.T) {
	r := &Role{Permissions: []string{"read"}}
	r.RemovePermission("read")
	assert.Empty(t, r.Permissions)
}

// ──────────────────────────────────────────────
// HasPermission
// ──────────────────────────────────────────────

func TestHasPermission_Exists(t *testing.T) {
	r := &Role{Permissions: []string{"read", "write"}}
	assert.True(t, r.HasPermission("read"))
	assert.True(t, r.HasPermission("write"))
}

func TestHasPermission_NotExists(t *testing.T) {
	r := &Role{Permissions: []string{"read"}}
	assert.False(t, r.HasPermission("write"))
	assert.False(t, r.HasPermission(""))
}

func TestHasPermission_EmptyRole(t *testing.T) {
	r := &Role{Permissions: []string{}}
	assert.False(t, r.HasPermission("read"))
}

// ──────────────────────────────────────────────
// Role lifecycle
// ──────────────────────────────────────────────

func TestRole_SoftDelete(t *testing.T) {
	r := NewRole("admin", nil)
	assert.False(t, r.IsDeleted())
	r.SoftDelete()
	assert.True(t, r.IsDeleted())
	assert.NotNil(t, r.DeletedAt)
}

func TestNewRole_Initialization(t *testing.T) {
	desc := "Administrator role"
	r := NewRole("admin", &desc)
	assert.NotEmpty(t, r.ID)
	assert.Equal(t, "admin", r.Name)
	assert.Equal(t, &desc, r.Description)
	assert.NotNil(t, r.Permissions)
	assert.NotNil(t, r.Metadata)
}
