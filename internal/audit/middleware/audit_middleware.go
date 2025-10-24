// Package middleware 提供智能审计中间件，实现业务逻辑与审计关注点的优雅分离
package middleware

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"gosso/internal/audit/auditor"
	"gosso/internal/audit/domain"
)

// AuditMiddleware 审计中间件核心
type AuditMiddleware struct {
	auditor auditor.Auditor
	db      *gorm.DB
}

// NewAuditMiddleware 创建审计中间件
func NewAuditMiddleware(db *gorm.DB, auditor auditor.Auditor) *AuditMiddleware {
	return &AuditMiddleware{
		auditor: auditor,
		db:      db,
	}
}

// WithAudit 创建审计执行器（泛型函数）
func WithAudit[T any](
	ctx context.Context,
	am *AuditMiddleware,
	action string,
	actor string,
) *AuditExecutor[T] {
	return &AuditExecutor[T]{
		middleware: am,
		ctx:        ctx,
		action:     action,
		actor:      actor,
		sync:       true, // 默认同步
		meta:       make(map[string]interface{}),
	}
}

// AuditExecutor 审计执行器
type AuditExecutor[T any] struct {
	middleware *AuditMiddleware
	ctx        context.Context
	action     string
	actor      string
	sync       bool
	meta       map[string]interface{}
}

// Async 设置为异步审计
func (ae *AuditExecutor[T]) Async() *AuditExecutor[T] {
	ae.sync = false
	return ae
}

// WithMeta 添加元数据
func (ae *AuditExecutor[T]) WithMeta(key string, value interface{}) *AuditExecutor[T] {
	ae.meta[key] = value
	return ae
}

// Do 执行业务逻辑并自动审计
func (ae *AuditExecutor[T]) Do(businessFunc func(tx *gorm.DB) (*T, error)) error {
	return ae.middleware.db.Transaction(func(tx *gorm.DB) error {
		// 执行业务逻辑
		result, err := businessFunc(tx)
		if err != nil {
			return err
		}

		// 自动构建并写入审计事件
		return ae.autoAudit(tx, result)
	})
}

// autoAudit 自动构建审计事件
func (ae *AuditExecutor[T]) autoAudit(tx *gorm.DB, result *T) error {
	event := &domain.AuditEvent{
		TxID:      uuid.New(),
		Actor:     ae.actor,
		Action:    ae.action,
		CreatedAt: time.Now(),
	}

	// 智能提取资源信息
	if result != nil {
		ae.extractResourceInfo(event, result)
	}

	// 添加元数据
	if len(ae.meta) > 0 {
		metaJSON, _ := json.Marshal(ae.meta)
		event.Meta = json.RawMessage(metaJSON)
	}

	// 选择同步或异步
	if ae.sync {
		return ae.middleware.auditor.LogTx(ae.ctx, tx, event)
	} else {
		pending := ae.buildPendingFromEvent(event)
		return ae.middleware.auditor.EnqueuePending(ae.ctx, tx, pending)
	}
}

// extractResourceInfo 智能提取资源信息
func (ae *AuditExecutor[T]) extractResourceInfo(event *domain.AuditEvent, obj *T) {
	if obj == nil {
		return
	}

	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// 如果不是结构体，尝试处理 map 类型
	if v.Kind() == reflect.Map {
		ae.extractFromMap(event, v)
		return
	}

	if v.Kind() != reflect.Struct {
		return
	}

	// 提取资源类型
	resourceType := strings.ToLower(v.Type().Name())

	// 自动提取ID和AccountID
	var resourceID string
	var accountID *uuid.UUID

	if idField := v.FieldByName("ID"); idField.IsValid() {
		if id, ok := idField.Interface().(uuid.UUID); ok {
			resourceID = id.String()
		}
	}

	if accField := v.FieldByName("AccountID"); accField.IsValid() {
		if accField.Kind() == reflect.Ptr && !accField.IsNil() {
			if id, ok := accField.Interface().(*uuid.UUID); ok {
				accountID = id
			}
		}
	}

	event.AccountID = accountID

	// 构建资源信息
	resourceData := map[string]interface{}{
		"type": resourceType,
		"id":   resourceID,
	}
	resourceJSON, _ := json.Marshal(resourceData)
	event.Resource = json.RawMessage(resourceJSON)

	// 构建新值信息（过滤敏感字段）
	newData := ae.extractFieldsForAudit(v)
	if len(newData) > 0 {
		newJSON, _ := json.Marshal(newData)
		event.New = json.RawMessage(newJSON)
	}
}

// extractFromMap 从 map 类型提取信息
func (ae *AuditExecutor[T]) extractFromMap(event *domain.AuditEvent, v reflect.Value) {
	mapData := v.Interface().(map[string]interface{})

	// 尝试提取 account_id
	if accountIDStr, ok := mapData["account_id"].(string); ok {
		if accountID, err := uuid.Parse(accountIDStr); err == nil {
			event.AccountID = &accountID
		}
	}

	// 构建资源信息
	resourceData := map[string]interface{}{
		"type": "event",
		"data": mapData,
	}
	resourceJSON, _ := json.Marshal(resourceData)
	event.Resource = json.RawMessage(resourceJSON)

	// 将整个 map 作为新值
	newJSON, _ := json.Marshal(mapData)
	event.New = json.RawMessage(newJSON)
}

// extractFieldsForAudit 提取审计字段（过滤敏感信息）
func (ae *AuditExecutor[T]) extractFieldsForAudit(value reflect.Value) map[string]interface{} {
	result := make(map[string]interface{})
	if value.Kind() != reflect.Struct {
		return result
	}

	valueType := value.Type()

	// 需要跳过的敏感字段
	skipFields := map[string]bool{
		"CreatedAt": true, "UpdatedAt": true, "DeletedAt": true,
		"Password": true, "Secret": true, "Token": true, "Hash": true,
	}

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := valueType.Field(i)

		// 跳过不可导出字段和敏感字段
		if !field.CanInterface() || skipFields[fieldType.Name] {
			continue
		}

		// 跳过 nil 指针
		if field.Kind() == reflect.Ptr && field.IsNil() {
			continue
		}

		fieldName := strings.ToLower(fieldType.Name)
		fieldValue := field.Interface()

		// 特殊处理 UUID 类型
		if uuidObj, ok := fieldValue.(uuid.UUID); ok {
			result[fieldName] = uuidObj.String()
		} else if uuidPtr, ok := fieldValue.(*uuid.UUID); ok && uuidPtr != nil {
			result[fieldName] = uuidPtr.String()
		} else {
			result[fieldName] = fieldValue
		}
	}

	return result
}

// buildPendingFromEvent 从审计事件构建待处理记录
func (ae *AuditExecutor[T]) buildPendingFromEvent(event *domain.AuditEvent) *domain.AuditPending {
	// 将完整的审计事件序列化为 payload
	eventJSON, _ := json.Marshal(event)

	return &domain.AuditPending{
		ID:        uuid.New(),
		TxID:      event.TxID,
		AccountID: event.AccountID,
		Action:    event.Action,
		Payload:   json.RawMessage(eventJSON),
		Attempts:  0,
	}
}
