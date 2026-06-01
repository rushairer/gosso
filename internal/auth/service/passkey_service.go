package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/rushairer/gosso/internal/auth/domain"
	"github.com/rushairer/gosso/internal/auth/repository"
	"github.com/rushairer/gosso/internal/cache"
	"go.uber.org/zap"
)

const (
	challengeTTL          = 5 * time.Minute
	redisKeyRegChallenge  = "webauthn:reg:%s"
	redisKeyLoginChallenge = "webauthn:login:%s"
	redisKeyMFAChallenge  = "webauthn:mfa:%s"
)

// PasskeyCredentialView passkey 列表视图（不暴露敏感数据）
type PasskeyCredentialView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	AttestationType string     `json:"attestation_type"`
	Transports      []string   `json:"transports,omitempty"`
}

// PasskeyService WebAuthn Passkey 服务
type PasskeyService struct {
	web      *wa.WebAuthn
	credRepo repository.WebAuthnCredentialRepository
	redis    *cache.RedisClient
	db       *sql.DB
	logger   *zap.Logger
}

// NewPasskeyService 创建 Passkey 服务实例
func NewPasskeyService(
	web *wa.WebAuthn,
	credRepo repository.WebAuthnCredentialRepository,
	redis *cache.RedisClient,
	db *sql.DB,
	logger *zap.Logger,
) *PasskeyService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &PasskeyService{
		web:      web,
		credRepo: credRepo,
		redis:    redis,
		db:       db,
		logger:   logger,
	}
}

// BeginRegistration 开始 Passkey 注册，返回 CredentialCreation options
func (s *PasskeyService) BeginRegistration(ctx context.Context, accountID, username, displayName string) (*protocol.CredentialCreation, error) {
	// 查找已有 credentials 用于排除
	existingCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Warn("Failed to find existing credentials", zap.Error(err))
		existingCreds = nil
	}

	user := domain.NewWebAuthnUser(accountID, username, displayName, toCredentialSlice(existingCreds))

	options, sessionData, err := s.web.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	// 存储 challenge 到 Redis
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyRegChallenge, accountID)
	if err := s.redis.Set(ctx, key, data, challengeTTL); err != nil {
		return nil, fmt.Errorf("store challenge: %w", err)
	}

	return options, nil
}

// CompleteRegistration 完成 Passkey 注册
func (s *PasskeyService) CompleteRegistration(ctx context.Context, accountID, username, displayName string, request *http.Request) (*domain.WebAuthnCredential, error) {
	// 从 Redis 获取 challenge
	key := fmt.Sprintf(redisKeyRegChallenge, accountID)
	data, err := s.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("challenge not found or expired")
	}
	_ = s.redis.Del(ctx, key)

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	// 查找已有 credentials
	existingCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		existingCreds = nil
	}

	user := domain.NewWebAuthnUser(accountID, username, displayName, toCredentialSlice(existingCreds))

	credential, err := s.web.FinishRegistration(user, sessionData, request)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	// 保存 credential 到数据库
	now := time.Now()
	cred := &domain.WebAuthnCredential{
		ID:              newUUID(),
		AccountID:       accountID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		SignCount:       credential.Authenticator.SignCount,
		AAGUID:          credential.Authenticator.AAGUID,
		Transports:      transportsToStrings(credential.Transport),
		AttestationType: credential.AttestationType,
		Name:            "Passkey",
		Verified:        true,
		CreatedAt:       now,
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credRepo.CreateCredential(ctx, tx, cred); err != nil {
		return nil, fmt.Errorf("save credential: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	s.logger.Info("Passkey registered",
		zap.String("account_id", accountID),
		zap.String("credential_id", cred.ID))

	return cred, nil
}

// BeginLogin 开始 Passkey 登录（MFA 场景，已知 accountID）
func (s *PasskeyService) BeginLogin(ctx context.Context, accountID string) (*protocol.CredentialAssertion, string, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil || len(creds) == 0 {
		return nil, "", fmt.Errorf("no passkey found for account")
	}

	user := domain.NewWebAuthnUser(accountID, "", "", toCredentialSlice(creds))

	options, sessionData, err := s.web.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin login: %w", err)
	}

	// 使用随机 requestID 存储 challenge
	requestID := newUUID()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyLoginChallenge, requestID)
	if err := s.redis.Set(ctx, key, data, challengeTTL); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return options, requestID, nil
}

// BeginDiscoverableLogin 开始无密码登录（不知道 accountID）
func (s *PasskeyService) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	options, sessionData, err := s.web.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("begin discoverable login: %w", err)
	}

	requestID := newUUID()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyLoginChallenge, requestID)
	if err := s.redis.Set(ctx, key, data, challengeTTL); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return options, requestID, nil
}

// CompleteLogin 完成 Passkey 登录验证
func (s *PasskeyService) CompleteLogin(ctx context.Context, requestID string, request *http.Request) (string, *domain.WebAuthnCredential, error) {
	// 从 Redis 获取 challenge
	key := fmt.Sprintf(redisKeyLoginChallenge, requestID)
	data, err := s.redis.Get(ctx, key)
	if err != nil {
		return "", nil, fmt.Errorf("challenge not found or expired")
	}
	_ = s.redis.Del(ctx, key)

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return "", nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	// 解析 response 获取 credential ID
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(request.Body)
	if err != nil {
		return "", nil, fmt.Errorf("parse credential response: %w", err)
	}

	credID := parsedResponse.RawID
	cred, err := s.credRepo.FindByCredentialID(ctx, string(credID))
	if err != nil {
		return "", nil, fmt.Errorf("credential not found")
	}

	// 查找该账号的所有 credentials
	allCreds, err := s.credRepo.FindByAccountID(ctx, cred.AccountID)
	if err != nil {
		return "", nil, fmt.Errorf("find credentials: %w", err)
	}

	user := domain.NewWebAuthnUser(cred.AccountID, "", "", toCredentialSlice(allCreds))

	waCred, err := s.web.FinishLogin(user, sessionData, request)
	if err != nil {
		return "", nil, fmt.Errorf("finish login: %w", err)
	}

	// 更新 sign count
	cred.SignCount = waCred.Authenticator.SignCount
	cred.MarkUsed()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credRepo.UpdateCredential(ctx, tx, cred); err != nil {
		s.logger.Warn("Failed to update credential sign count", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		s.logger.Warn("Failed to commit credential update", zap.Error(err))
	}

	return cred.AccountID, cred, nil
}

// BeginMFALogin 开始 MFA Passkey 验证
func (s *PasskeyService) BeginMFALogin(ctx context.Context, accountID string) (*protocol.CredentialAssertion, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil || len(creds) == 0 {
		return nil, fmt.Errorf("no passkey found for account")
	}

	user := domain.NewWebAuthnUser(accountID, "", "", toCredentialSlice(creds))

	options, sessionData, err := s.web.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("begin mfa login: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyMFAChallenge, accountID)
	if err := s.redis.Set(ctx, key, data, challengeTTL); err != nil {
		return nil, fmt.Errorf("store challenge: %w", err)
	}

	return options, nil
}

// CompleteMFALogin 完成 MFA Passkey 验证
func (s *PasskeyService) CompleteMFALogin(ctx context.Context, accountID string, request *http.Request) error {
	key := fmt.Sprintf(redisKeyMFAChallenge, accountID)
	data, err := s.redis.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("challenge not found or expired")
	}
	_ = s.redis.Del(ctx, key)

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return fmt.Errorf("unmarshal session data: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(request.Body)
	if err != nil {
		return fmt.Errorf("parse credential response: %w", err)
	}

	credID := parsedResponse.RawID
	cred, err := s.credRepo.FindByCredentialID(ctx, string(credID))
	if err != nil {
		return fmt.Errorf("credential not found")
	}

	if cred.AccountID != accountID {
		return fmt.Errorf("credential does not belong to account")
	}

	allCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		return fmt.Errorf("find credentials: %w", err)
	}

	user := domain.NewWebAuthnUser(accountID, "", "", toCredentialSlice(allCreds))

	waCred, err := s.web.FinishLogin(user, sessionData, request)
	if err != nil {
		return fmt.Errorf("finish mfa login: %w", err)
	}

	cred.SignCount = waCred.Authenticator.SignCount
	cred.MarkUsed()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credRepo.UpdateCredential(ctx, tx, cred); err != nil {
		s.logger.Warn("Failed to update credential", zap.Error(err))
	}

	return tx.Commit()
}

// HasPasskeys 检查账号是否有可用的 passkey
func (s *PasskeyService) HasPasskeys(ctx context.Context, accountID string) (bool, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

// ListCredentials 列出账号的所有 passkeys
func (s *PasskeyService) ListCredentials(ctx context.Context, accountID string) ([]PasskeyCredentialView, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find credentials: %w", err)
	}

	views := make([]PasskeyCredentialView, 0, len(creds))
	for _, c := range creds {
		views = append(views, PasskeyCredentialView{
			ID:              c.ID,
			Name:            c.Name,
			CreatedAt:       c.CreatedAt,
			LastUsedAt:      c.LastUsedAt,
			AttestationType: c.AttestationType,
			Transports:      c.Transports,
		})
	}
	return views, nil
}

// DeleteCredential 删除 passkey（ownership check）
func (s *PasskeyService) DeleteCredential(ctx context.Context, accountID, credentialID string) error {
	cred, err := s.credRepo.FindByCredentialID(ctx, credentialID)
	if err != nil {
		return fmt.Errorf("credential not found")
	}

	if cred.AccountID != accountID {
		return fmt.Errorf("credential does not belong to account")
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credRepo.SoftDeleteCredential(ctx, tx, cred.ID, time.Now()); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	s.logger.Info("Passkey deleted",
		zap.String("account_id", accountID),
		zap.String("credential_id", cred.ID))

	return nil
}

// toCredentialSlice 将 []*domain.WebAuthnCredential 转换为 []domain.WebAuthnCredential
func toCredentialSlice(creds []*domain.WebAuthnCredential) []domain.WebAuthnCredential {
	if creds == nil {
		return nil
	}
	result := make([]domain.WebAuthnCredential, len(creds))
	for i, c := range creds {
		result[i] = *c
	}
	return result
}

// transportsToStrings 将 protocol.AuthenticatorTransport 转换为 []string
func transportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	if len(transports) == 0 {
		return nil
	}
	result := make([]string, len(transports))
	for i, t := range transports {
		result[i] = string(t)
	}
	return result
}
