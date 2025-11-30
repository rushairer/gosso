package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role 角色领域模型
type Role struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Permissions []string   `json:"permissions"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

// NewRole 创建新角色
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

// IsDeleted 是否已软删除
func (r *Role) IsDeleted() bool {
	return r.DeletedAt != nil
}

// SoftDelete 软删除角色
func (r *Role) SoftDelete() {
	now := time.Now()
	r.DeletedAt = &now
	r.UpdatedAt = now
}

// AddPermission 添加权限
func (r *Role) AddPermission(permission string) {
	// 检查是否已存在
	for _, p := range r.Permissions {
		if p == permission {
			return
		}
	}
	r.Permissions = append(r.Permissions, permission)
	r.UpdatedAt = time.Now()
}

// RemovePermission 移除权限
func (r *Role) RemovePermission(permission string) {
	for i, p := range r.Permissions {
		if p == permission {
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			r.UpdatedAt = time.Now()
			return
		}
	}
}

// HasPermission 检查是否有某个权限
func (r *Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// Group 群组领域模型
type Group struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	ParentID    *string    `json:"parent_id,omitempty"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

// NewGroup 创建新群组
func NewGroup(name string, description *string, parentID *string) *Group {
	return &Group{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		ParentID:    parentID,
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// IsDeleted 是否已软删除
func (g *Group) IsDeleted() bool {
	return g.DeletedAt != nil
}

// SoftDelete 软删除群组
func (g *Group) SoftDelete() {
	now := time.Now()
	g.DeletedAt = &now
	g.UpdatedAt = now
}
