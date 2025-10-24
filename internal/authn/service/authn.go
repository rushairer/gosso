// Package service 提供认证服务的业务逻辑实现
package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"gosso/internal/audit/auditor"
	"gosso/internal/audit/middleware"
	"gosso/internal/authn/domain"
)

// AuthnService 认证服务
type AuthnService struct {
	db    *gorm.DB
	audit *middleware.AuditMiddleware // 审计中间件
}

// NewAuthnService 创建认证服务实例
func NewAuthnService(db *gorm.DB, auditor auditor.Auditor) *AuthnService {
	return &AuthnService{
		db:    db,
		audit: middleware.NewAuditMiddleware(db, auditor),
	}
}

// BindCredential 绑定凭证到账号（同步审计）
func (s *AuthnService) BindCredential(ctx context.Context, accountID, credID uuid.UUID, actor string) error {
	return middleware.WithAudit[domain.Credential](ctx, s.audit, "credential.bind", actor).
		WithMeta("method", "bind").
		Do(func(tx *gorm.DB) (*domain.Credential, error) {
			// 纯净的业务逻辑
			var c domain.Credential
			if err := tx.WithContext(ctx).First(&c, "id = ?", credID).Error; err != nil {
				return nil, err
			}

			if c.AccountID != nil && *c.AccountID != accountID {
				return nil, errors.New("credential is already bound to another account")
			}

			c.AccountID = &accountID
			if err := tx.WithContext(ctx).Save(&c).Error; err != nil {
				return nil, err
			}

			return &c, nil
		})
}

// SetPrimaryCredential 设置主凭证（同步审计）
func (s *AuthnService) SetPrimaryCredential(ctx context.Context, accountID, targetCredID uuid.UUID, actor string) error {
	return middleware.WithAudit[domain.Credential](ctx, s.audit, "credential.set_primary", actor).
		WithMeta("method", "set_primary").
		Do(func(tx *gorm.DB) (*domain.Credential, error) {
			// 验证凭证存在且属于该账号
			var target domain.Credential
			if err := tx.WithContext(ctx).First(&target, "id = ?", targetCredID).Error; err != nil {
				return nil, err
			}

			if target.AccountID == nil || *target.AccountID != accountID {
				return nil, errors.New("credential is not owned by this account")
			}

			if target.VerifiedAt == nil {
				return nil, errors.New("credential is not verified")
			}

			// 清理旧的主凭证
			if err := tx.Model(&domain.Credential{}).
				Where("account_id = ? AND is_primary = true", accountID).
				Update("is_primary", false).Error; err != nil {
				return nil, err
			}

			// 设置新的主凭证
			target.IsPrimary = true
			if err := tx.WithContext(ctx).Save(&target).Error; err != nil {
				return nil, err
			}

			// 更新账号的主凭证ID
			if err := tx.Model(&domain.Account{}).
				Where("id = ?", accountID).
				Update("primary_credential_id", targetCredID).Error; err != nil {
				return nil, err
			}

			return &target, nil
		})
}

// MergeAccount 合并账号（同步审计 - 关键操作）
func (s *AuthnService) MergeAccount(ctx context.Context, sourceAccountID, targetAccountID uuid.UUID, actor string) error {
	return middleware.WithAudit[map[string]interface{}](ctx, s.audit, "account.merge", actor).
		WithMeta("method", "merge").
		WithMeta("critical", true).
		Do(func(tx *gorm.DB) (*map[string]interface{}, error) {
			// 验证源账号和目标账号存在
			var sourceAccount, targetAccount domain.Account
			if err := tx.WithContext(ctx).First(&sourceAccount, "id = ?", sourceAccountID).Error; err != nil {
				return nil, errors.New("source account not found")
			}
			if err := tx.WithContext(ctx).First(&targetAccount, "id = ?", targetAccountID).Error; err != nil {
				return nil, errors.New("target account not found")
			}

			// 将源账号的所有凭证转移到目标账号
			if err := tx.Model(&domain.Credential{}).
				Where("account_id = ?", sourceAccountID).
				Update("account_id", targetAccountID).Error; err != nil {
				return nil, err
			}

			// 将源账号的资料转移到目标账号（如果目标账号资料为空）

			if err := tx.WithContext(ctx).Save(&targetAccount).Error; err != nil {
				return nil, err
			}

			// 软删除源账号
			if err := tx.WithContext(ctx).Delete(&sourceAccount).Error; err != nil {
				return nil, err
			}

			// 返回合并结果信息
			result := map[string]interface{}{
				"source_account_id": sourceAccountID.String(),
				"target_account_id": targetAccountID.String(),
				"merged_at":         time.Now(),
			}

			return &result, nil
		})
}

// Login 登录事件记录（异步审计 - 高频操作）
func (s *AuthnService) Login(ctx context.Context, accountID uuid.UUID, success bool, ip, userAgent, actor string) error {
	return middleware.WithAudit[map[string]interface{}](ctx, s.audit, "login", actor).
		Async(). // 异步处理，避免阻塞登录流程
		WithMeta("ip", ip).
		WithMeta("user_agent", userAgent).
		WithMeta("success", success).
		Do(func(tx *gorm.DB) (*map[string]interface{}, error) {
			// 登录相关的业务逻辑（如更新最后登录时间等）
			if success {
				// 更新账号最后登录时间
				now := time.Now()
				if err := tx.Model(&domain.Account{}).
					Where("id = ?", accountID).
					Updates(map[string]interface{}{
						"last_login_at": &now,
						"login_count":   gorm.Expr("login_count + 1"),
					}).Error; err != nil {
					return nil, err
				}
			}

			// 构建登录事件数据
			result := map[string]interface{}{
				"account_id": accountID.String(),
				"success":    success,
				"ip":         ip,
				"user_agent": userAgent,
				"timestamp":  time.Now(),
			}

			return &result, nil
		})
}

// VerifyCredential 验证凭证（同步审计）
func (s *AuthnService) VerifyCredential(ctx context.Context, credID uuid.UUID, actor string) error {
	return middleware.WithAudit[domain.Credential](ctx, s.audit, "credential.verify", actor).
		WithMeta("method", "verify").
		Do(func(tx *gorm.DB) (*domain.Credential, error) {
			var c domain.Credential
			if err := tx.WithContext(ctx).First(&c, "id = ?", credID).Error; err != nil {
				return nil, err
			}

			// 设置验证时间
			now := time.Now()
			c.VerifiedAt = &now
			c.Status = "active"

			if err := tx.WithContext(ctx).Save(&c).Error; err != nil {
				return nil, err
			}

			return &c, nil
		})
}

// DeleteCredential 删除凭证（同步审计 - 敏感操作）
func (s *AuthnService) DeleteCredential(ctx context.Context, credID uuid.UUID, actor string) error {
	return middleware.WithAudit[domain.Credential](ctx, s.audit, "credential.delete", actor).
		WithMeta("method", "delete").
		WithMeta("sensitive", true).
		Do(func(tx *gorm.DB) (*domain.Credential, error) {
			var c domain.Credential
			if err := tx.WithContext(ctx).First(&c, "id = ?", credID).Error; err != nil {
				return nil, err
			}

			// 如果是主凭证，需要先取消主凭证状态
			if c.IsPrimary && c.AccountID != nil {
				if err := tx.Model(&domain.Account{}).
					Where("id = ?", *c.AccountID).
					Update("primary_credential_id", nil).Error; err != nil {
					return nil, err
				}
			}

			// 软删除凭证
			if err := tx.WithContext(ctx).Delete(&c).Error; err != nil {
				return nil, err
			}

			return &c, nil
		})
}
