package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/utility"
)

// OAuthProviderConfig single OAuth provider configuration
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

// SocialLoginService social login service
type SocialLoginService struct {
	db                    *sql.DB
	accountSvc            accountService.AccountService
	sessionTokenCreator   SessionTokenCreator
	mfaChecker            MFAChecker
	accountRepo           accountRepo.AccountRepository
	credentialRepo        accountRepo.CredentialRepository
	federatedIdentityRepo accountRepo.FederatedIdentityRepository
	providers             map[string]*OAuthProviderConfig
	httpClient            *http.Client
	auditor               *auditService.Auditor
	logger                *zap.Logger
}

// NewSocialLoginService creates a social login service
func NewSocialLoginService(
	db *sql.DB,
	accountSvc accountService.AccountService,
	sessionTokenCreator SessionTokenCreator,
	accountRepo accountRepo.AccountRepository,
	credentialRepo accountRepo.CredentialRepository,
	federatedIdentityRepo accountRepo.FederatedIdentityRepository,
	providers map[string]*OAuthProviderConfig,
	logger *zap.Logger,
) *SocialLoginService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SocialLoginService{
		db:                    db,
		accountSvc:            accountSvc,
		sessionTokenCreator:   sessionTokenCreator,
		accountRepo:           accountRepo,
		credentialRepo:        credentialRepo,
		federatedIdentityRepo: federatedIdentityRepo,
		providers:             providers,
		httpClient:            &http.Client{Timeout: 10 * time.Second},
		logger:                logger,
	}
}

// SetMFAChecker sets the MFA checker dependency (setter injection to avoid circular constructor deps).
func (s *SocialLoginService) SetMFAChecker(checker MFAChecker) {
	s.mfaChecker = checker
}

// SetAuditor sets the audit service dependency (setter injection to avoid circular constructor deps).
func (s *SocialLoginService) SetAuditor(auditor *auditService.Auditor) {
	s.auditor = auditor
}

// GetAuthURL gets the third-party authorization URL
func (s *SocialLoginService) GetAuthURL(ctx context.Context, provider, state string) (string, error) {
	p, ok := s.providers[provider]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedProvider, provider)
	}

	if p.AuthURL == "" {
		return "", fmt.Errorf("auth URL not configured for provider: %s", provider)
	}

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("redirect_uri", p.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.Scopes, " "))
	params.Set("state", state)

	return p.AuthURL + "?" + params.Encode(), nil
}

// HandleCallback handles the third-party callback
func (s *SocialLoginService) HandleCallback(ctx context.Context, provider, code, ip, userAgent string) (*LoginResult, error) {
	if s.mfaChecker == nil {
		s.logger.Error("SocialLoginService: MFAChecker not set, this is a programming error")
		return nil, ErrSocialMisconfigured
	}

	p, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, provider)
	}

	// 1. Exchange code for access_token
	accessToken, err := s.exchangeCode(ctx, p, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	// 2. Fetch user info
	providerUserID, email, name, emailVerified, err := s.fetchUserInfo(ctx, provider, p, accessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch user info: %w", err)
	}

	// 3. Find existing federated identity
	identity, err := s.federatedIdentityRepo.FindByProvider(ctx, accountDomain.Provider(provider), providerUserID)
	if err == nil && identity != nil {
		// Existing identity -> login directly
		return s.loginExistingUser(ctx, identity.AccountID, ip, userAgent)
	}

	// 4. New user -> create account + bind identity
	return s.createNewUser(ctx, provider, providerUserID, email, name, emailVerified, ip, userAgent)
}

func (s *SocialLoginService) exchangeCode(ctx context.Context, p *OAuthProviderConfig, code string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("redirect_uri", p.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", errors.New("no access_token in response")
	}

	return tokenResp.AccessToken, nil
}

func (s *SocialLoginService) fetchUserInfo(ctx context.Context, provider string, p *OAuthProviderConfig, accessToken string) (providerUserID, email, name string, emailVerified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.UserInfoURL, nil)
	if err != nil {
		return "", "", "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", false, fmt.Errorf("userinfo request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", "", false, fmt.Errorf("read userinfo: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", "", false, fmt.Errorf("userinfo request failed: %d", resp.StatusCode)
	}

	var userInfo map[string]any
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return "", "", "", false, fmt.Errorf("parse userinfo: %w", err)
	}

	switch provider {
	case "google", "github":
		if idVal, ok := userInfo["id"].(float64); ok {
			providerUserID = fmt.Sprintf("%.0f", idVal)
		} else if idStr, ok := userInfo["id"].(string); ok {
			providerUserID = idStr
		} else {
			return "", "", "", false, fmt.Errorf("%s: missing or invalid id field", provider)
		}
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
		emailVerified, _ = userInfo["email_verified"].(bool)
	case "wechat":
		openid, ok := userInfo["openid"].(string)
		if !ok || openid == "" {
			return "", "", "", false, fmt.Errorf("wechat: missing or empty openid")
		}
		providerUserID = openid
		nickname, _ := userInfo["nickname"].(string)
		name = nickname
		// WeChat does not provide email_verified; default false
	default:
		return "", "", "", false, fmt.Errorf("%w: %s", ErrUnsupportedProvider, provider)
	}

	return providerUserID, email, name, emailVerified, nil
}

func (s *SocialLoginService) loginExistingUser(ctx context.Context, accountID, ip, userAgent string) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			accountUUID, _ := uuid.Parse(accountID)
			auditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
				auditDomain.ActionLoginFailure,
				audit.IPFromContext(ctx),
				&accountUUID,
				utility.MustMarshalJSON(map[string]any{"method": "social", "account_id": accountID}),
				utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx), "reason": safeAuditReason(err)}),
			))
		}
	}()

	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}

	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrAccountNotActive
	}

	// Check if MFA is required before issuing tokens
	if s.mfaChecker != nil {
		mfaResult, mfaErr := s.mfaChecker.CheckMFA(ctx, account)
		if mfaResult != nil || mfaErr != nil {
			return mfaResult, mfaErr
		}
	}

	session, accessToken, refreshToken, err := s.sessionTokenCreator.CreateSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}

func (s *SocialLoginService) createNewUser(ctx context.Context, provider, providerUserID, email, name string, emailVerified bool, ip, userAgent string) (*LoginResult, error) {
	// If email is provided, check if an account already exists with that email.
	// This prevents duplicate accounts when a user registers via email/password first
	// and later uses social login with the same email.
	if email != "" {
		existingCred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, accountDomain.CredentialTypeEmail, email)
		if err == nil && existingCred != nil && existingCred.IsVerified() {
			// Link federated identity to existing account (only if email is verified,
			// preventing account takeover via an unverified email from a social provider).
			identity := accountDomain.NewFederatedIdentity(existingCred.AccountID, accountDomain.Provider(provider), providerUserID, nil)
			linkErr := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
				return s.federatedIdentityRepo.CreateFederatedIdentity(ctx, tx, identity)
			})
			if linkErr != nil {
				if isUniqueViolation(linkErr) {
					// Another concurrent request already linked this identity; proceed with login
					return s.loginExistingUser(ctx, existingCred.AccountID, ip, userAgent)
				}
				return nil, fmt.Errorf("link federated identity: %w", linkErr)
			}
			return s.loginExistingUser(ctx, existingCred.AccountID, ip, userAgent)
		}
	}

	if name == "" {
		name = "User"
	}

	account := accountDomain.NewAccount(name)

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.accountRepo.CreateAccount(ctx, tx, account); err != nil {
			return fmt.Errorf("create account: %w", err)
		}

		if email != "" {
			emailCred := accountDomain.NewEmailCredential(account.ID, email)
			emailCred.PrimaryCredential = true
			if emailVerified {
				emailCred.Verify()
			}
			if err := s.credentialRepo.CreateCredentials(ctx, tx, []*accountDomain.Credential{emailCred}); err != nil {
				return fmt.Errorf("create email credential: %w", err)
			}
		}

		identity := accountDomain.NewFederatedIdentity(account.ID, accountDomain.Provider(provider), providerUserID, nil)
		if err := s.federatedIdentityRepo.CreateFederatedIdentity(ctx, tx, identity); err != nil {
			return fmt.Errorf("create federated identity: %w", err)
		}

		return nil
	})
	if err != nil {
		// Handle race condition: concurrent social logins with the same email.
		// The pre-check above passed, but another request created the account between the check and the transaction.
		// The DB unique constraint on (credential_type, identifier) caught it — fall back to linking.
		if email != "" && isUniqueViolation(err) {
			existingCred, findErr := s.credentialRepo.FindByTypeAndIdentifier(ctx, accountDomain.CredentialTypeEmail, email)
			if findErr == nil && existingCred != nil && existingCred.IsVerified() {
				identity := accountDomain.NewFederatedIdentity(existingCred.AccountID, accountDomain.Provider(provider), providerUserID, nil)
				linkErr := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
					return s.federatedIdentityRepo.CreateFederatedIdentity(ctx, tx, identity)
				})
				if linkErr != nil {
					if isUniqueViolation(linkErr) {
						return s.loginExistingUser(ctx, existingCred.AccountID, ip, userAgent)
					}
					return nil, fmt.Errorf("link federated identity after race: %w", linkErr)
				}
				return s.loginExistingUser(ctx, existingCred.AccountID, ip, userAgent)
			}
		}
		return nil, err
	}

	// Audit log for social login account creation
	accountUUID, _ := uuid.Parse(account.ID)
	auditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionAccountRegister,
		audit.IPFromContext(ctx),
		&accountUUID,
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID, "provider": provider}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	// Check if MFA is required (consistency with loginExistingUser)
	if s.mfaChecker != nil {
		mfaResult, mfaErr := s.mfaChecker.CheckMFA(ctx, account)
		if mfaResult != nil || mfaErr != nil {
			return mfaResult, mfaErr
		}
	}

	session, accessToken, refreshToken, err := s.sessionTokenCreator.CreateSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}

// isUniqueViolation checks if an error is a PostgreSQL unique constraint violation.
// This handles race conditions where concurrent requests pass an existence check
// but the DB constraint catches the duplicate.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
