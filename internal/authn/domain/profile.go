package domain

import (
	"time"

	"github.com/google/uuid"
)

// Profile 存放与用户可见相关的属性，独立于 Account，以便于隐私与查询性能的分离。
// 说明：
// - Profile 使用 AccountID 作为主键（每个 account 最多一条 profile）；
// - Data 字段用于存放任意扩展信息（jsonb），避免频繁修改结构。
type Profile struct {
	AccountID   uuid.UUID              `json:"account_id" gorm:"type:uuid;primaryKey"`                                        // 与 account 一一对应
	DisplayName string                 `json:"display_name,omitempty" gorm:"type:varchar(255);index:idx_profile_displayname"` // 展示名
	FirstName   string                 `json:"first_name,omitempty" gorm:"type:varchar(100);index:idx_profile_firstname"`     // 名
	LastName    string                 `json:"last_name,omitempty" gorm:"type:varchar(100);index:idx_profile_lastname"`       // 姓
	Locale      string                 `json:"locale,omitempty" gorm:"type:varchar(16)"`                                      // 语言/地区
	Timezone    string                 `json:"timezone,omitempty" gorm:"type:varchar(64)"`                                    // 时区
	AvatarURL   string                 `json:"avatar_url,omitempty" gorm:"type:text"`                                         // 头像链接
	Data        map[string]interface{} `json:"data,omitempty" gorm:"type:jsonb"`                                              // 任意扩展字段（jsonb）
	CreatedAt   time.Time              `json:"created_at" gorm:"autoCreateTime"`                                              // 创建时间
	UpdatedAt   time.Time              `json:"updated_at" gorm:"autoUpdateTime"`                                              // 更新时间
}

// TableName 指定 GORM 使用的表名
func (Profile) TableName() string {
	return "profiles"
}
