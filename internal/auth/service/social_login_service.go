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

	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	dbutil "github.com/rushairer/gosso/internal/db"
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

// GetAuthURL gets the third-party authorization URL
func (s *SocialLoginService) GetAuthURL(ctx context.Context, provider, state string) (string, error) {
	p, ok := s.providers[provider]
	if !ok {
		return "", fmt.Errorf("unsupported provider: %s", provider)
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
		return nil, fmt.Errorf("social login service misconfigured: mfa checker not set")
	}

	p, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	// 1. Exchange code for access_token
	accessToken, err := s.exchangeCode(ctx, p, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	// 2. Fetch user info
	providerUserID, email, name, err := s.fetchUserInfo(ctx, provider, p, accessToken)
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
	return s.createNewUser(ctx, provider, providerUserID, email, name, ip, userAgent)
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

func (s *SocialLoginService) fetchUserInfo(ctx context.Context, provider string, p *OAuthProviderConfig, accessToken string) (providerUserID, email, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.UserInfoURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("userinfo request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", "", fmt.Errorf("read userinfo: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("userinfo request failed: %d", resp.StatusCode)
	}

	var userInfo map[string]any
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return "", "", "", fmt.Errorf("parse userinfo: %w", err)
	}

	switch provider {
	case "google":
		providerUserID = fmt.Sprintf("%.0f", userInfo["id"].(float64))
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
	case "github":
		providerUserID = fmt.Sprintf("%.0f", userInfo["id"])
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
	case "wechat":
		providerUserID, _ = userInfo["openid"].(string)
		nickname, _ := userInfo["nickname"].(string)
		name = nickname
	default:
		return "", "", "", fmt.Errorf("unsupported provider: %s", provider)
	}

	return providerUserID, email, name, nil
}

func (s *SocialLoginService) loginExistingUser(ctx context.Context, accountID, ip, userAgent string) (*LoginResult, error) {
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}

	if account.Status != accountDomain.AccountStatusActive {
		return nil, errors.New("account is not active")
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

func (s *SocialLoginService) createNewUser(ctx context.Context, provider, providerUserID, email, name, ip, userAgent string) (*LoginResult, error) {
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
			emailCred.Verify()
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
		return nil, err
	}

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
