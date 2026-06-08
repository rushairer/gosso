package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/auth/domain"
	"github.com/rushairer/gosso/internal/auth/repository"
	"github.com/rushairer/gosso/internal/cache"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/utility"
)

// AccountLookup provides account lookup for passkey registration name resolution.
type AccountLookup interface {
	FindAccountByID(ctx context.Context, accountID string) (*accountDomain.Account, error)
}

const (
	defaultChallengeTTL    = 5 * time.Minute
	redisKeyRegChallenge   = "webauthn:reg:%s"
	redisKeyLoginChallenge = "webauthn:login:%s"
	redisKeyMFAChallenge   = "webauthn:mfa:%s"
)

// PasskeyCredentialView passkey list view (does not expose sensitive data)
type PasskeyCredentialView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	AttestationType string     `json:"attestation_type"`
	Transports      []string   `json:"transports,omitempty"`
}

const maxPasskeyRequestBodySize = 64 << 10 // 64KB — WebAuthn payloads are CBOR-encoded

// PasskeyService WebAuthn Passkey service
type PasskeyService struct {
	web           *wa.WebAuthn
	credRepo      repository.WebAuthnCredentialRepository
	redis         *cache.RedisClient
	db            *sql.DB
	accountLookup AccountLookup
	logger        *zap.Logger
	challengeTTL  time.Duration
}

// NewPasskeyService creates a new PasskeyService instance
func NewPasskeyService(
	web *wa.WebAuthn,
	credRepo repository.WebAuthnCredentialRepository,
	redis *cache.RedisClient,
	db *sql.DB,
	accountLookup AccountLookup,
	logger *zap.Logger,
) *PasskeyService {
	logger = utility.EnsureLogger(logger)
	return &PasskeyService{
		web:           web,
		credRepo:      credRepo,
		redis:         redis,
		db:            db,
		accountLookup: accountLookup,
		logger:        logger,
		challengeTTL:  defaultChallengeTTL,
	}
}

// SetChallengeTTL overrides the WebAuthn challenge TTL.
// Must be called during initialization; not safe for concurrent use.
func (s *PasskeyService) SetChallengeTTL(d time.Duration) {
	if d > 0 {
		s.challengeTTL = d
	}
}

// BeginRegistration starts Passkey registration, returning CredentialCreation options
func (s *PasskeyService) BeginRegistration(ctx context.Context, accountID, username, displayName string) (*protocol.CredentialCreation, error) {
	// Find existing credentials for exclusion
	existingCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Error("Failed to find existing credentials during registration", zap.Error(err), zap.String("account_id", accountID))
		return nil, fmt.Errorf("find existing credentials: %w", err)
	}

	user := domain.NewWebAuthnUser(accountID, username, displayName, toCredentialSlice(existingCreds))

	options, sessionData, err := s.web.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	// Store challenge to Redis
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyRegChallenge, accountID)
	if err := s.redis.Set(ctx, key, data, s.challengeTTL); err != nil {
		return nil, fmt.Errorf("store challenge: %w", err)
	}

	return options, nil
}

// CompleteRegistration completes Passkey registration
func (s *PasskeyService) CompleteRegistration(ctx context.Context, accountID, username, displayName string, request *http.Request) (*domain.WebAuthnCredential, error) {
	// Get challenge from Redis
	key := fmt.Sprintf(redisKeyRegChallenge, accountID)
	data, err := s.redis.GetDel(ctx, key)
	if err != nil {
		return nil, ErrChallengeNotFound
	}

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	// Find existing credentials
	existingCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		existingCreds = nil
	}

	user := domain.NewWebAuthnUser(accountID, username, displayName, toCredentialSlice(existingCreds))

	credential, err := s.web.FinishRegistration(user, sessionData, request)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	// Save credential to database
	now := time.Now()
	cred := &domain.WebAuthnCredential{
		ID:              uuid.New().String(),
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

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credRepo.CreateCredential(ctx, tx, cred)
	})
	if err != nil {
		return nil, fmt.Errorf("save credential: %w", err)
	}

	s.logger.Info("Passkey registered",
		zap.String("account_id", accountID),
		zap.String("credential_id", cred.ID))

	return cred, nil
}

// BeginLogin starts Passkey login (MFA scenario, known accountID)
func (s *PasskeyService) BeginLogin(ctx context.Context, accountID string) (*protocol.CredentialAssertion, string, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil || len(creds) == 0 {
		return nil, "", ErrPasskeyNotFound
	}

	user := domain.NewWebAuthnUser(accountID, "", "", toCredentialSlice(creds))

	options, sessionData, err := s.web.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin login: %w", err)
	}

	// Store challenge using random requestID
	requestID := uuid.New().String()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyLoginChallenge, requestID)
	if err := s.redis.Set(ctx, key, data, s.challengeTTL); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return options, requestID, nil
}

// BeginDiscoverableLogin starts passwordless login (unknown accountID)
func (s *PasskeyService) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	options, sessionData, err := s.web.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("begin discoverable login: %w", err)
	}

	requestID := uuid.New().String()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(redisKeyLoginChallenge, requestID)
	if err := s.redis.Set(ctx, key, data, s.challengeTTL); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return options, requestID, nil
}

// CompleteLogin completes Passkey login verification
func (s *PasskeyService) CompleteLogin(ctx context.Context, requestID string, request *http.Request) (string, *domain.WebAuthnCredential, error) {
	// Get challenge from Redis
	key := fmt.Sprintf(redisKeyLoginChallenge, requestID)
	data, err := s.redis.GetDel(ctx, key)
	if err != nil {
		return "", nil, ErrChallengeNotFound
	}

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return "", nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	// Buffer the body so it can be read twice (once for parsing, once by FinishLogin)
	bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, maxPasskeyRequestBodySize+1))
	if err != nil {
		return "", nil, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(bodyBytes)) > maxPasskeyRequestBodySize {
		return "", nil, ErrRequestBodyTooLarge
	}
	request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse response to get credential ID
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(io.NopCloser(bytes.NewReader(bodyBytes)))
	if err != nil {
		return "", nil, fmt.Errorf("parse credential response: %w", err)
	}

	credID := parsedResponse.RawID
	cred, err := s.credRepo.FindByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credID))
	if err != nil {
		return "", nil, ErrCredentialNotFound
	}

	// Find all credentials for this account
	allCreds, err := s.credRepo.FindByAccountID(ctx, cred.AccountID)
	if err != nil {
		return "", nil, fmt.Errorf("find credentials: %w", err)
	}

	user := domain.NewWebAuthnUser(cred.AccountID, "", "", toCredentialSlice(allCreds))

	waCred, err := s.web.FinishLogin(user, sessionData, request)
	if err != nil {
		return "", nil, fmt.Errorf("finish login: %w", err)
	}

	// Update sign count
	cred.SignCount = waCred.Authenticator.SignCount
	cred.MarkUsed()

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credRepo.UpdateCredential(ctx, tx, cred)
	})
	if err != nil {
		s.logger.Error("Failed to update credential sign count — clone detection may be compromised",
			zap.Error(err),
			zap.String("account_id", cred.AccountID),
			zap.String("credential_id", cred.ID))
		return "", nil, fmt.Errorf("update credential sign count: %w", err)
	}

	return cred.AccountID, cred, nil
}

// BeginMFALogin starts MFA Passkey verification
func (s *PasskeyService) BeginMFALogin(ctx context.Context, accountID string) (*protocol.CredentialAssertion, string, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil || len(creds) == 0 {
		return nil, "", ErrPasskeyNotFound
	}

	user := domain.NewWebAuthnUser(accountID, "", "", toCredentialSlice(creds))

	options, sessionData, err := s.web.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin mfa login: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	requestID := uuid.New().String()
	key := fmt.Sprintf(redisKeyMFAChallenge, requestID)
	if err := s.redis.Set(ctx, key, data, s.challengeTTL); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return options, requestID, nil
}

// CompleteMFALogin completes MFA Passkey verification
func (s *PasskeyService) CompleteMFALogin(ctx context.Context, requestID string, accountID string, request *http.Request) error {
	key := fmt.Sprintf(redisKeyMFAChallenge, requestID)
	data, err := s.redis.GetDel(ctx, key)
	if err != nil {
		return ErrChallengeNotFound
	}

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return fmt.Errorf("unmarshal session data: %w", err)
	}

	// Buffer the body so it can be read twice (once for parsing, once by FinishLogin)
	bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, maxPasskeyRequestBodySize+1))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if int64(len(bodyBytes)) > maxPasskeyRequestBodySize {
		return ErrRequestBodyTooLarge
	}
	request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(io.NopCloser(bytes.NewReader(bodyBytes)))
	if err != nil {
		return fmt.Errorf("parse credential response: %w", err)
	}

	credID := parsedResponse.RawID
	cred, err := s.credRepo.FindByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credID))
	if err != nil {
		return ErrCredentialNotFound
	}

	if cred.AccountID != accountID {
		return ErrCredentialOwnership
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

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credRepo.UpdateCredential(ctx, tx, cred)
	})
	if err != nil {
		s.logger.Error("Failed to update credential sign count — clone detection may be compromised",
			zap.Error(err),
			zap.String("account_id", cred.AccountID),
			zap.String("credential_id", cred.ID))
		return fmt.Errorf("update credential sign count: %w", err)
	}

	return nil
}

// HasPasskeys checks if the account has any available passkey
func (s *PasskeyService) HasPasskeys(ctx context.Context, accountID string) (bool, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

// ListCredentials lists all passkeys for the account
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

// DeleteCredential deletes a passkey (ownership check)
func (s *PasskeyService) DeleteCredential(ctx context.Context, accountID, credentialID string) error {
	cred, err := s.credRepo.FindByCredentialID(ctx, credentialID)
	if err != nil {
		return ErrCredentialNotFound
	}

	if cred.AccountID != accountID {
		return ErrCredentialOwnership
	}

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credRepo.SoftDeleteCredential(ctx, tx, cred.ID, time.Now())
	})
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	s.logger.Info("Passkey deleted",
		zap.String("account_id", accountID),
		zap.String("credential_id", cred.ID))

	return nil
}

// toCredentialSlice converts []*domain.WebAuthnCredential to []domain.WebAuthnCredential
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

// transportsToStrings converts []protocol.AuthenticatorTransport to []string
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

// ResolveAccountForRegistration resolves the account and derives username/displayName for passkey registration.
// Falls back to accountID when username/displayName are not set on the account.
func (s *PasskeyService) ResolveAccountForRegistration(ctx context.Context, accountID string) (username, displayName string, err error) {
	account, err := s.accountLookup.FindAccountByID(ctx, accountID)
	if err != nil {
		return "", "", fmt.Errorf("resolve account: %w", err)
	}

	username = accountID
	if account.Username != nil {
		username = *account.Username
	}
	displayName = username
	if account.DisplayName != "" {
		displayName = account.DisplayName
	}
	return username, displayName, nil
}
