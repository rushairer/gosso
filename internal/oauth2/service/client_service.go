package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/oauth2/repository"
	"golang.org/x/crypto/bcrypt"
)

// RegisterClientRequest 注册 OAuth2 客户端请求
type RegisterClientRequest struct {
	AccountID      string
	Name           string
	Description    string
	RedirectURIs   []string
	GrantTypes     []string
	Scopes         []string
	IsConfidential bool
	Metadata       map[string]any
}

// OAuth2ClientService OAuth2 客户端服务接口
type OAuth2ClientService interface {
	RegisterClient(ctx context.Context, req *RegisterClientRequest) (*domain.OAuth2Client, string, error)
	FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error)
	FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error)
	UpdateClient(ctx context.Context, client *domain.OAuth2Client) error
	DeleteClient(ctx context.Context, id string) error
}

type oauth2ClientServiceImpl struct {
	db       *sql.DB
	clientRepo repository.OAuth2ClientRepository
}

// NewOAuth2ClientService 创建 OAuth2 客户端服务实例
func NewOAuth2ClientService(db *sql.DB, clientRepo repository.OAuth2ClientRepository) OAuth2ClientService {
	return &oauth2ClientServiceImpl{
		db:         db,
		clientRepo: clientRepo,
	}
}

func (s *oauth2ClientServiceImpl) RegisterClient(ctx context.Context, req *RegisterClientRequest) (*domain.OAuth2Client, string, error) {
	clientID := generateClientID()
	var secretPlaintext string
	var secretHash string

	if req.IsConfidential {
		secretPlaintext = generateClientSecret()
		hash, err := bcrypt.GenerateFromPassword([]byte(secretPlaintext), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("hash client secret: %w", err)
		}
		secretHash = string(hash)
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{domain.GrantTypeAuthorizationCode}
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	client := &domain.OAuth2Client{
		AccountID:        req.AccountID,
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		Name:             req.Name,
		Description:      req.Description,
		RedirectURIs:     req.RedirectURIs,
		GrantTypes:       grantTypes,
		Scopes:           scopes,
		IsConfidential:   req.IsConfidential,
		Metadata:         req.Metadata,
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, "", fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.clientRepo.Create(ctx, tx, client); err != nil {
		return nil, "", err
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit transaction: %w", err)
	}

	return client, secretPlaintext, nil
}

func (s *oauth2ClientServiceImpl) FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	return s.clientRepo.FindByClientID(ctx, clientID)
}

func (s *oauth2ClientServiceImpl) FindByAccountID(ctx context.Context, accountID string) ([]*domain.OAuth2Client, error) {
	return s.clientRepo.FindByAccountID(ctx, accountID)
}

func (s *oauth2ClientServiceImpl) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.clientRepo.Update(ctx, tx, client); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *oauth2ClientServiceImpl) DeleteClient(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.clientRepo.SoftDelete(ctx, tx, id, time.Now()); err != nil {
		return err
	}

	return tx.Commit()
}

// generateClientID 生成 24 字节的 client_id（48 字符 hex）
func generateClientID() string {
	bytes := make([]byte, 24)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateClientSecret 生成 32 字节的 client_secret（64 字符 hex）
func generateClientSecret() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
