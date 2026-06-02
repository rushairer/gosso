package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/mail"
	"regexp"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/utility"
)

// AccountService 账号服务接口
type AccountService interface {
	// RegisterAccount 注册账号（邮箱/手机 + 密码）
	RegisterAccount(ctx context.Context, req *RegisterAccountRequest) (*domain.Account, error)

	// FindAccountByID 根据 ID 查找账号
	FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error)

	// FindAccountByUsername 根据用户名查找账号
	FindAccountByUsername(ctx context.Context, username string) (*domain.Account, error)

	// UpdateAccount 更新账号信息
	UpdateAccount(ctx context.Context, account *domain.Account) error

	// SoftDeleteAccount 软删除账号（级联删除所有关联数据）
	SoftDeleteAccount(ctx context.Context, accountID string) error

	// VerifyCredential 验证凭证（邮箱/手机）
	VerifyCredential(ctx context.Context, credentialID string) error

	// ChangePassword 修改密码
	ChangePassword(ctx context.Context, accountID, oldPassword, newPassword string) error

	// BindFederatedIdentity 绑定第三方身份
	BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]interface{}) error

	// UnbindFederatedIdentity 解绑第三方身份
	UnbindFederatedIdentity(ctx context.Context, identityID string) error

	// AssignRole 为账号分配角色
	AssignRole(ctx context.Context, accountID, roleID string) error

	// RemoveRole 移除账号的角色
	RemoveRole(ctx context.Context, accountID, roleID string) error

	// ListAccounts 分页查询账号列表（管理员用）
	ListAccounts(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error)

	// SuspendAccount 禁用账号
	SuspendAccount(ctx context.Context, accountID string) error

	// ActivateAccount 启用账号
	ActivateAccount(ctx context.Context, accountID string) error

	// GetAccountRoles 获取账号的角色列表
	GetAccountRoles(ctx context.Context, accountID string) ([]*domain.Role, error)
}

// RegisterAccountRequest 注册账号请求
type RegisterAccountRequest struct {
	Username    string         // 用户名（可选）
	DisplayName string         // 显示名称
	Email       string         // 邮箱（可选）
	Phone       string         // 手机号（可选）
	Password    string         // 密码（必须）
	Locale      string         // 语言偏好
	Timezone    string         // 时区
	Metadata    map[string]any // 扩展元数据
}

type accountServiceImpl struct {
	db                    *sql.DB
	accountRepo           repository.AccountRepository
	credentialRepo        repository.CredentialRepository
	federatedIdentityRepo repository.FederatedIdentityRepository
	roleRepo              repository.RoleRepository
	auditor               *auditService.Auditor
}

// NewAccountService 创建账号服务
func NewAccountService(
	db *sql.DB,
	accountRepo repository.AccountRepository,
	credentialRepo repository.CredentialRepository,
	federatedIdentityRepo repository.FederatedIdentityRepository,
	roleRepo repository.RoleRepository,
	auditor *auditService.Auditor,
) AccountService {
	return &accountServiceImpl{
		db:                    db,
		accountRepo:           accountRepo,
		credentialRepo:        credentialRepo,
		federatedIdentityRepo: federatedIdentityRepo,
		roleRepo:              roleRepo,
		auditor:               auditor,
	}
}

// RegisterAccount 注册账号
func (s *accountServiceImpl) RegisterAccount(ctx context.Context, req *RegisterAccountRequest) (*domain.Account, error) {
	// 1. 业务验证
	if err := s.validateRegistration(req); err != nil {
		return nil, fmt.Errorf("验证失败: %w", err)
	}

	// 2. 检查凭证是否已存在
	if req.Email != "" {
		if err := s.checkCredentialExists(ctx, domain.CredentialTypeEmail, req.Email); err != nil {
			return nil, err
		}
	}
	if req.Phone != "" {
		if err := s.checkCredentialExists(ctx, domain.CredentialTypePhone, req.Phone); err != nil {
			return nil, err
		}
	}

	// 3. 开始事务
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return nil, fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback() // 忽略 Rollback 错误（Commit 后 Rollback 会失败，这是预期行为）
	}()

	now := time.Now()

	// 4. 创建账号
	var username *string
	if req.Username != "" {
		username = &req.Username
	}

	account := &domain.Account{
		ID:          uuid.New().String(),
		Username:    username,
		DisplayName: req.DisplayName,
		Status:      domain.AccountStatusActive,
		Locale:      req.Locale,
		Timezone:    req.Timezone,
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.accountRepo.CreateAccount(ctx, tx, account); err != nil {
		return nil, err
	}

	// 5. 创建凭证列表
	var credentials []*domain.Credential

	// 5.1 创建密码凭证
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("哈希密码失败: %w", err)
	}

	passwordCred := &domain.Credential{
		ID:                uuid.New().String(),
		AccountID:         account.ID,
		Type:              domain.CredentialTypePassword,
		Value:             string(passwordHash),
		Verified:          true,
		PrimaryCredential: false,
		Metadata:          make(map[string]interface{}),
		CreatedAt:         now,
	}
	credentials = append(credentials, passwordCred)

	// 5.2 创建邮箱凭证
	if req.Email != "" {
		emailCred := &domain.Credential{
			ID:                uuid.New().String(),
			AccountID:         account.ID,
			Type:              domain.CredentialTypeEmail,
			Identifier:        &req.Email,
			Verified:          false,
			PrimaryCredential: true,
			Metadata:          make(map[string]interface{}),
			CreatedAt:         now,
		}
		credentials = append(credentials, emailCred)
	}

	// 5.3 创建手机凭证
	if req.Phone != "" {
		phoneCred := &domain.Credential{
			ID:                uuid.New().String(),
			AccountID:         account.ID,
			Type:              domain.CredentialTypePhone,
			Identifier:        &req.Phone,
			Verified:          false,
			PrimaryCredential: req.Email == "", // 如果没有邮箱，手机为主要凭证
			Metadata:          make(map[string]interface{}),
			CreatedAt:         now,
		}
		credentials = append(credentials, phoneCred)
	}

	// 6. 批量创建凭证
	if err := s.credentialRepo.CreateCredentials(ctx, tx, credentials); err != nil {
		return nil, err
	}

	// 7. 提交事务
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交事务失败: %w", err)
	}

	// 8. 审计日志
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountRegister,
		audit.IPFromContext(ctx),
		parseUUID(account.ID),
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return account, nil
}

// FindAccountByID 根据 ID 查找账号
func (s *accountServiceImpl) FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error) {
	return s.accountRepo.FindByID(ctx, accountID)
}

// FindAccountByUsername 根据用户名查找账号
func (s *accountServiceImpl) FindAccountByUsername(ctx context.Context, username string) (*domain.Account, error) {
	return s.accountRepo.FindByUsername(ctx, username)
}

// UpdateAccount 更新账号信息
func (s *accountServiceImpl) UpdateAccount(ctx context.Context, account *domain.Account) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	account.UpdatedAt = time.Now()

	if err := s.accountRepo.UpdateAccount(ctx, tx, account); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

// SoftDeleteAccount 软删除账号（级联删除所有关联数据）
func (s *accountServiceImpl) SoftDeleteAccount(ctx context.Context, accountID string) error {
	// 1. 业务验证
	if accountID == "" {
		return fmt.Errorf("账号 ID 不能为空")
	}

	// 2. 开始事务
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now()

	// 3. 软删除关联数据（按依赖关系顺序）
	if err := s.credentialRepo.SoftDeleteCredentialsByAccount(ctx, tx, accountID, now); err != nil {
		return err
	}

	if err := s.federatedIdentityRepo.SoftDeleteByAccountID(ctx, tx, accountID, now); err != nil {
		return err
	}

	if err := s.roleRepo.SoftDeleteRolesByAccountID(ctx, tx, accountID, now); err != nil {
		return err
	}

	// 4. 最后软删除账号
	if err := s.accountRepo.SoftDeleteAccount(ctx, tx, accountID, now); err != nil {
		return err
	}

	// 5. 提交事务
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	// 6. 审计日志
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountDelete,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return nil
}

// VerifyCredential 验证凭证
func (s *accountServiceImpl) VerifyCredential(ctx context.Context, credentialID string) error {
	// 1. 查找凭证
	credentials, err := s.credentialRepo.FindByAccountAndType(ctx, credentialID, domain.CredentialTypeEmail)
	if err != nil || len(credentials) == 0 {
		// 尝试查找手机凭证
		credentials, err = s.credentialRepo.FindByAccountAndType(ctx, credentialID, domain.CredentialTypePhone)
		if err != nil || len(credentials) == 0 {
			return fmt.Errorf("凭证不存在")
		}
	}

	credential := credentials[0]

	// 2. 标记为已验证
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	credential.Verify()

	if err := s.credentialRepo.UpdateCredential(ctx, tx, credential); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

// ChangePassword 修改密码
func (s *accountServiceImpl) ChangePassword(ctx context.Context, accountID, oldPassword, newPassword string) error {
	// 1. 查找密码凭证
	passwordCred, err := s.credentialRepo.FindPasswordCredential(ctx, accountID)
	if err != nil {
		return fmt.Errorf("查找密码凭证失败: %w", err)
	}

	// 2. 验证旧密码
	if !passwordCred.VerifyPassword(oldPassword) {
		return fmt.Errorf("旧密码错误")
	}

	// 3. 生成新密码哈希
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("哈希新密码失败: %w", err)
	}

	// 4. 更新密码
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	passwordCred.Value = string(newPasswordHash)

	if err := s.credentialRepo.UpdateCredential(ctx, tx, passwordCred); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	// 5. 审计日志
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionPasswordChange,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return nil
}

// BindFederatedIdentity 绑定第三方身份
func (s *accountServiceImpl) BindFederatedIdentity(ctx context.Context, accountID string, provider domain.Provider, providerUserID string, profile map[string]interface{}) error {
	// 1. 检查是否已绑定
	existing, err := s.federatedIdentityRepo.FindByProvider(ctx, provider, providerUserID)
	if err == nil && existing != nil {
		return fmt.Errorf("该第三方账号已被绑定")
	}

	// 2. 创建绑定
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now()
	identity := &domain.FederatedIdentity{
		ID:             uuid.New().String(),
		AccountID:      accountID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Profile:        profile,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.federatedIdentityRepo.CreateFederatedIdentity(ctx, tx, identity); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

// UnbindFederatedIdentity 解绑第三方身份
func (s *accountServiceImpl) UnbindFederatedIdentity(ctx context.Context, identityID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now()

	if err := s.federatedIdentityRepo.SoftDeleteByID(ctx, tx, identityID, now); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

// AssignRole 为账号分配角色
func (s *accountServiceImpl) AssignRole(ctx context.Context, accountID, roleID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := s.roleRepo.AssignRoleToAccount(ctx, tx, accountID, roleID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionRoleAssign,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "role_id": roleID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// RemoveRole 移除账号的角色
func (s *accountServiceImpl) RemoveRole(ctx context.Context, accountID, roleID string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now()

	if err := s.roleRepo.RemoveRoleFromAccount(ctx, tx, accountID, roleID, now); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionRoleRemove,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID, "role_id": roleID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// ListAccounts 分页查询账号列表
func (s *accountServiceImpl) ListAccounts(ctx context.Context, page, pageSize int, status string) ([]*domain.Account, int, error) {
	return s.accountRepo.FindAll(ctx, page, pageSize, status)
}

// SuspendAccount 禁用账号
func (s *accountServiceImpl) SuspendAccount(ctx context.Context, accountID string) error {
	account, err := s.accountRepo.FindByID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("查找账号失败: %w", err)
	}

	if !account.IsActive() {
		return fmt.Errorf("账号状态不允许禁用: %s", account.Status)
	}

	account.Suspend()
	if err := s.UpdateAccount(ctx, account); err != nil {
		return err
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountSuspend,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// ActivateAccount 启用账号
func (s *accountServiceImpl) ActivateAccount(ctx context.Context, accountID string) error {
	account, err := s.accountRepo.FindByID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("查找账号失败: %w", err)
	}

	if !account.IsSuspended() {
		return fmt.Errorf("账号状态不允许启用: %s", account.Status)
	}

	account.Activate()
	if err := s.UpdateAccount(ctx, account); err != nil {
		return err
	}

	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionAccountActivate,
		audit.IPFromContext(ctx),
		parseUUID(accountID),
		utility.MustMarshalJSON(map[string]any{"account_id": accountID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))
	return nil
}

// GetAccountRoles 获取账号的角色列表
func (s *accountServiceImpl) GetAccountRoles(ctx context.Context, accountID string) ([]*domain.Role, error) {
	return s.roleRepo.FindRolesByAccountID(ctx, accountID)
}

// validateRegistration 验证注册请求
var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{6,14}$`)

func (s *accountServiceImpl) validateRegistration(req *RegisterAccountRequest) error {
	if req.Password == "" {
		return fmt.Errorf("密码不能为空")
	}

	if len(req.Password) < 8 {
		return fmt.Errorf("密码长度不能少于 8 位")
	}

	// 密码强度检查：至少包含大写、小写、数字各一个
	var hasUpper, hasLower, hasDigit bool
	for _, c := range req.Password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("密码必须包含大写字母、小写字母和数字")
	}

	if req.Email == "" && req.Phone == "" {
		return fmt.Errorf("邮箱和手机号至少提供一个")
	}

	if req.DisplayName == "" {
		return fmt.Errorf("显示名称不能为空")
	}

	// 邮箱格式验证
	if req.Email != "" {
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return fmt.Errorf("邮箱格式不正确")
		}
	}

	// 手机号格式验证
	if req.Phone != "" {
		if !phoneRegex.MatchString(req.Phone) {
			return fmt.Errorf("手机号格式不正确")
		}
	}

	return nil
}

// checkCredentialExists 检查凭证是否已存在
func (s *accountServiceImpl) checkCredentialExists(ctx context.Context, credType domain.CredentialType, identifier string) error {
	cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, credType, identifier)
	if err == nil && cred != nil {
		switch credType {
		case domain.CredentialTypeEmail:
			return fmt.Errorf("邮箱已被注册")
		case domain.CredentialTypePhone:
			return fmt.Errorf("手机号已被注册")
		}
	}
	return nil
}

func (s *accountServiceImpl) auditLog(ctx context.Context, record *auditDomain.AuditRecord) {
	if s.auditor != nil {
		_ = s.auditor.Log(ctx, record)
	}
}

func parseUUID(s string) *uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}
