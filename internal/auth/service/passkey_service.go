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
	accountRepository "github.com/rushairer/gosso/internal/account/repository"
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

// NewPasskeyService creates a new PasskeyService instance with default configuration.
func NewPasskeyService(
	web *wa.WebAuthn,
	credRepo repository.WebAuthnCredentialRepository,
	redis *cache.RedisClient,
	db *sql.DB,
	accountLookup AccountLookup,
	logger *zap.Logger,
) *PasskeyService {
	return NewPasskeyServiceWithConfig(web, credRepo, redis, db, accountLookup, logger, PasskeyServiceConfig{})
}

// PasskeyServiceConfig holds optional configuration for PasskeyService.
// Zero-valued fields fall back to package-level defaults.
type PasskeyServiceConfig struct {
	ChallengeTTL time.Duration // default: defaultChallengeTTL (5 min)
}

// NewPasskeyServiceWithConfig creates a new PasskeyService with explicit configuration.
func NewPasskeyServiceWithConfig(
	web *wa.WebAuthn,
	credRepo repository.WebAuthnCredentialRepository,
	redis *cache.RedisClient,
	db *sql.DB,
	accountLookup AccountLookup,
	logger *zap.Logger,
	cfg PasskeyServiceConfig,
) *PasskeyService {
	logger = utility.EnsureLogger(logger)
	challengeTTL := cfg.ChallengeTTL
	if challengeTTL <= 0 {
		challengeTTL = defaultChallengeTTL
	}
	return &PasskeyService{
		web:           web,
		credRepo:      credRepo,
		redis:         redis,
		db:            db,
		accountLookup: accountLookup,
		logger:        logger,
		challengeTTL:  challengeTTL,
	}
}

// SetChallengeTTL overrides the WebAuthn challenge TTL.
//
// Deprecated: Use NewPasskeyServiceWithConfig to set all options at construction time.
// Will be removed in v2.0.0.
func (s *PasskeyService) SetChallengeTTL(d time.Duration) {
	if d > 0 {
		s.challengeTTL = d
	}
}

// BeginRegistration starts Passkey registration, returning CredentialCreation options
// and a requestID that must be passed to CompleteRegistration.
// The requestID is used as the Redis challenge key (instead of accountID) to prevent
// concurrent registration flows from overwriting each other's challenges.
func (s *PasskeyService) BeginRegistration(ctx context.Context, accountID, username, displayName string) (*protocol.CredentialCreation, string, error) {
	// Find existing credentials for exclusion
	existingCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Error("Failed to find existing credentials during registration", zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(accountID)))
		return nil, "", fmt.Errorf("find existing credentials: %w", err)
	}

	user := domain.NewWebAuthnUser(accountID, username, displayName, toCredentialSlice(existingCreds))

	options, sessionData, err := s.web.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}

	// Store challenge to Redis keyed by random requestID
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	requestID := uuid.New().String()
	key := fmt.Sprintf(redisKeyRegChallenge, requestID)
	if err := s.redis.Set(ctx, key, data, s.challengeTTL); err != nil {
		return nil, "", fmt.Errorf("store challenge: %w", err)
	}

	return options, requestID, nil
}

// CompleteRegistration completes Passkey registration.
// requestID must match the one returned by BeginRegistration.
func (s *PasskeyService) CompleteRegistration(ctx context.Context, requestID, accountID, username, displayName string, request *http.Request) (*domain.WebAuthnCredential, error) {
	// Get challenge from Redis using the requestID
	key := fmt.Sprintf(redisKeyRegChallenge, requestID)
	data, err := s.redis.GetDel(ctx, key)
	if err != nil {
		return nil, ErrChallengeNotFound
	}

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	// Find existing credentials for exclusion list.
	// This is a security property — fail closed if we can't verify existing credentials.
	existingCreds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find existing credentials for exclusion list: %w", err)
	}

	user := domain.NewWebAuthnUser(accountID, username, displayName, toCredentialSlice(existingCreds))

	credential, err := s.web.FinishRegistration(user, sessionData, request)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	// Save credential to database
	cred, err := domain.NewWebAuthnCredential(
		accountID,
		credential.ID,
		credential.PublicKey,
		credential.AttestationType,
		transportsToStrings(credential.Transport),
		credential.Authenticator.SignCount,
		credential.Authenticator.AAGUID,
		"Passkey",
	)
	if err != nil {
		return nil, fmt.Errorf("create webauthn credential: %w", err)
	}
	cred.Verified = true

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credRepo.CreateCredential(ctx, tx, cred)
	})
	if err != nil {
		return nil, fmt.Errorf("save credential: %w", err)
	}

	s.logger.Info("Passkey registered",
		zap.String("account_id", utility.MaskOpaqueID(accountID)),
		zap.String("credential_id", cred.ID))

	return cred, nil
}

// BeginLogin starts Passkey login (login scenario, known accountID)
func (s *PasskeyService) BeginLogin(ctx context.Context, accountID string) (*protocol.CredentialAssertion, string, error) {
	return s.beginLoginInternal(ctx, accountID, redisKeyLoginChallenge, "login")
}

// BeginMFALogin starts MFA Passkey verification
func (s *PasskeyService) BeginMFALogin(ctx context.Context, accountID string) (*protocol.CredentialAssertion, string, error) {
	return s.beginLoginInternal(ctx, accountID, redisKeyMFAChallenge, "mfa")
}

// beginLoginInternal is the shared implementation for BeginLogin and BeginMFALogin.
func (s *PasskeyService) beginLoginInternal(ctx context.Context, accountID, keyPrefix, logAction string) (*protocol.CredentialAssertion, string, error) {
	creds, err := s.credRepo.FindByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Warn("Failed to find passkey credentials for "+logAction, zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		return nil, "", ErrPasskeyNotFound
	}
	if len(creds) == 0 {
		return nil, "", ErrPasskeyNotFound
	}

	user := domain.NewWebAuthnUser(accountID, "", "", toCredentialSlice(creds))

	options, sessionData, err := s.web.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin %s login: %w", logAction, err)
	}

	requestID := uuid.New().String()
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal session data: %w", err)
	}

	key := fmt.Sprintf(keyPrefix, requestID)
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
	cred, err := s.completeLoginInternal(ctx, requestID, "", redisKeyLoginChallenge, request)
	if err != nil {
		return "", nil, err
	}
	return cred.AccountID, cred, nil
}

// CompleteMFALogin completes MFA Passkey verification
func (s *PasskeyService) CompleteMFALogin(ctx context.Context, requestID string, accountID string, request *http.Request) error {
	_, err := s.completeLoginInternal(ctx, requestID, accountID, redisKeyMFAChallenge, request)
	return err
}

// completeLoginInternal is the shared implementation for CompleteLogin and CompleteMFALogin.
// When expectedAccountID is non-empty, ownership verification is performed (MFA scenario).
func (s *PasskeyService) completeLoginInternal(ctx context.Context, requestID, expectedAccountID, keyPrefix string, request *http.Request) (*domain.WebAuthnCredential, error) {
	key := fmt.Sprintf(keyPrefix, requestID)
	data, err := s.redis.GetDel(ctx, key)
	if err != nil {
		return nil, ErrChallengeNotFound
	}

	var sessionData wa.SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	// Buffer the body so it can be read twice (once for parsing, once by FinishLogin)
	bodyBytes, err := readLimitedBody(request.Body, maxPasskeyRequestBodySize)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(io.NopCloser(bytes.NewReader(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("parse credential response: %w", err)
	}

	credID := parsedResponse.RawID
	cred, err := s.credRepo.FindByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credID))
	if err != nil {
		return nil, accountRepository.ErrCredentialNotFound
	}

	// Ownership check for MFA scenario
	if expectedAccountID != "" && cred.AccountID != expectedAccountID {
		return nil, ErrCredentialOwnership
	}

	allCreds, err := s.credRepo.FindByAccountID(ctx, cred.AccountID)
	if err != nil {
		return nil, fmt.Errorf("find credentials: %w", err)
	}

	user := domain.NewWebAuthnUser(cred.AccountID, "", "", toCredentialSlice(allCreds))

	waCred, err := s.web.FinishLogin(user, sessionData, request)
	if err != nil {
		return nil, fmt.Errorf("finish login: %w", err)
	}

	// Update sign count for clone detection.
	// Per WebAuthn spec: sign count of 0 means the authenticator does not support
	// counters. Only update if the new count is non-zero (authenticator supports it).
	if waCred.Authenticator.SignCount > 0 {
		cred.SignCount = waCred.Authenticator.SignCount
	}
	cred.MarkUsed()

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credRepo.UpdateCredential(ctx, tx, cred)
	})
	if err != nil {
		// Per WebAuthn spec, sign count is a best-effort clone detection mechanism.
		// A database failure should not block a legitimate login.
		s.logger.Error("Failed to update credential sign count — clone detection may be compromised (login allowed to proceed)",
			zap.Error(err),
			zap.String("account_id", utility.MaskOpaqueID(cred.AccountID)),
			zap.String("credential_id", cred.ID))
	}

	return cred, nil
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
		return accountRepository.ErrCredentialNotFound
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
		zap.String("account_id", utility.MaskOpaqueID(accountID)),
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

// readLimitedBody reads the request body with a size limit and replaces it
// with a new reader so it can be read again.
func readLimitedBody(body io.ReadCloser, maxSize int64) ([]byte, error) {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(data)) > maxSize {
		return nil, ErrRequestBodyTooLarge
	}
	return data, nil
}
