package main

import (
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/utility"
)

// Metadata 字段使用示例
func main() {
	fmt.Println("========== Metadata 使用示例 ==========")

	// 示例 1: 创建账号时设置 Metadata
	createAccountExample()

	// 示例 2: 使用 MetadataHelper 安全访问
	metadataHelperExample()

	// 示例 3: 独立函数访问
	standaloneFunctionExample()

	// 示例 4: 实际业务场景
	businessScenarioExample()
}

func createAccountExample() {
	fmt.Println("=== 示例 1: 创建账号时设置 Metadata ===")

	account := &domain.Account{
		DisplayName: "张三",
		Metadata: map[string]any{
			"department":   "engineering",
			"level":        3,
			"hire_date":    time.Now().Unix(),
			"tags":         []string{"senior", "backend", "go"},
			"is_remote":    true,
			"annual_leave": 15,
		},
	}

	fmt.Printf("账号创建成功: %s\n", account.DisplayName)
	fmt.Printf("部门: %v\n", account.Metadata["department"])
	fmt.Printf("级别: %v\n", account.Metadata["level"])
	fmt.Printf("标签: %v\n", account.Metadata["tags"])
	fmt.Println()
}

func metadataHelperExample() {
	fmt.Println("=== 示例 2: 使用 MetadataHelper 安全访问 ===")

	// 模拟从数据库读取的账号数据（可能包含不同类型）
	account := &domain.Account{
		Metadata: map[string]any{
			"department":   "engineering",
			"level":        float64(3), // JSON 反序列化后是 float64
			"hire_date":    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
			"tags":         []interface{}{"senior", "backend"},
			"is_remote":    true,
			"annual_leave": 15.0,
			"settings": map[string]any{
				"theme": "dark",
				"lang":  "zh-CN",
			},
		},
	}

	helper := utility.NewMetadataHelper(account.Metadata)

	// 安全获取各种类型
	department := helper.GetString("department", "unknown")
	level := helper.GetInt("level", 1) // 自动处理 float64 -> int
	hireDate := helper.GetTime("hire_date", time.Time{})
	tags := helper.GetStringSlice("tags", nil)
	isRemote := helper.GetBool("is_remote", false)
	annualLeave := helper.GetInt("annual_leave", 10)
	settings := helper.GetMap("settings", nil)

	fmt.Printf("部门: %s\n", department)
	fmt.Printf("级别: %d\n", level)
	fmt.Printf("入职日期: %s\n", hireDate.Format("2006-01-02"))
	fmt.Printf("标签: %v\n", tags)
	fmt.Printf("远程办公: %v\n", isRemote)
	fmt.Printf("年假天数: %d\n", annualLeave)
	fmt.Printf("偏好设置: %v\n", settings)

	// 修改 Metadata
	helper.Set("last_update", time.Now().Unix())
	helper.Set("updated_by", "admin")

	fmt.Printf("更新后的 Metadata 字段数: %d\n", len(helper.GetAll()))
	fmt.Println()
}

func standaloneFunctionExample() {
	fmt.Println("=== 示例 3: 独立函数访问 ===")

	metadata := map[string]any{
		"name":  "Alice",
		"age":   float64(28),
		"admin": true,
	}

	name := utility.GetStringValue(metadata, "name", "Unknown")
	age := utility.GetIntValue(metadata, "age", 0)
	isAdmin := utility.GetBoolValue(metadata, "admin", false)
	email := utility.GetStringValue(metadata, "email", "no-email")

	fmt.Printf("姓名: %s\n", name)
	fmt.Printf("年龄: %d\n", age)
	fmt.Printf("管理员: %v\n", isAdmin)
	fmt.Printf("邮箱: %s (使用默认值)\n", email)

	// 条件设置
	utility.SetIfNotEmpty(metadata, "nickname", "Ally")
	utility.SetIfNotEmpty(metadata, "empty_field", "")
	utility.SetIfNotZero(metadata, "score", 95)
	utility.SetIfNotZero(metadata, "zero_field", 0)

	fmt.Printf("设置后的字段: %v\n", metadata)
	fmt.Println()
}

func businessScenarioExample() {
	fmt.Println("=== 示例 4: 实际业务场景 - 权限检查 ===")

	// 模拟角色数据
	role := &domain.Role{
		Name: "project_manager",
		Metadata: map[string]any{
			"max_projects":    10,
			"can_approve":     true,
			"approval_limit":  float64(50000),
			"allowed_regions": []interface{}{"cn-north", "cn-south"},
			"restrictions": map[string]any{
				"working_hours": "9:00-18:00",
				"ip_whitelist":  []string{"192.168.1.0/24"},
			},
		},
	}

	helper := utility.NewMetadataHelper(role.Metadata)

	// 业务逻辑：检查权限限制
	fmt.Printf("角色: %s\n", role.Name)

	maxProjects := helper.GetInt("max_projects", 5)
	fmt.Printf("最大项目数: %d\n", maxProjects)

	canApprove := helper.GetBool("can_approve", false)
	if canApprove {
		approvalLimit := helper.GetFloat64("approval_limit", 10000)
		fmt.Printf("审批权限: 是 (限额: ¥%.2f)\n", approvalLimit)
	} else {
		fmt.Println("审批权限: 否")
	}

	allowedRegions := helper.GetStringSlice("allowed_regions", []string{"default"})
	fmt.Printf("允许的区域: %v\n", allowedRegions)

	restrictions := helper.GetMap("restrictions", nil)
	if restrictions != nil {
		fmt.Println("限制条件:")
		for key, value := range restrictions {
			fmt.Printf("  - %s: %v\n", key, value)
		}
	}

	// 动态添加审计信息
	helper.Set("last_used", time.Now().Unix())
	helper.Set("usage_count", 1)

	fmt.Println()
}
