// Package instance owns runtime, non-secret configuration for one GOSSO instance.
package instance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"go.uber.org/zap"

	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

var ErrInvalidSettings = errors.New("invalid instance settings")

type Settings struct {
	ProductName        string `json:"product_name"`
	LogoURL            string `json:"logo_url"`
	FaviconURL         string `json:"favicon_url"`
	PrimaryColor       string `json:"primary_color"`
	LoginTitle         string `json:"login_title"`
	LoginDescription   string `json:"login_description"`
	LoginBackgroundURL string `json:"login_background_url"`
	SupportEmail       string `json:"support_email"`
	SupportURL         string `json:"support_url"`
	PrivacyPolicyURL   string `json:"privacy_policy_url"`
	TermsOfServiceURL  string `json:"terms_of_service_url"`
	DefaultLocale      string `json:"default_locale"`
}

func DefaultSettings() Settings {
	return Settings{ProductName: "GOSSO", PrimaryColor: "#3b82f6", DefaultLocale: "en"}
}

// PublicBranding excludes secret and operational configuration metadata.
type PublicBranding struct {
	ProductName        string `json:"product_name"`
	LogoURL            string `json:"logo_url"`
	FaviconURL         string `json:"favicon_url"`
	PrimaryColor       string `json:"primary_color"`
	LoginTitle         string `json:"login_title"`
	LoginDescription   string `json:"login_description"`
	LoginBackgroundURL string `json:"login_background_url"`
	SupportEmail       string `json:"support_email"`
	SupportURL         string `json:"support_url"`
	PrivacyPolicyURL   string `json:"privacy_policy_url"`
	TermsOfServiceURL  string `json:"terms_of_service_url"`
	DefaultLocale      string `json:"default_locale"`
}

func (s Settings) PublicBranding() PublicBranding {
	return PublicBranding{
		ProductName: s.ProductName, LogoURL: s.LogoURL, FaviconURL: s.FaviconURL, PrimaryColor: s.PrimaryColor,
		LoginTitle: s.LoginTitle, LoginDescription: s.LoginDescription, LoginBackgroundURL: s.LoginBackgroundURL,
		SupportEmail: s.SupportEmail, SupportURL: s.SupportURL, PrivacyPolicyURL: s.PrivacyPolicyURL,
		TermsOfServiceURL: s.TermsOfServiceURL, DefaultLocale: s.DefaultLocale,
	}
}

type Service struct {
	db      *sql.DB
	auditor *auditService.Auditor
	logger  *zap.Logger
}

func NewService(db *sql.DB, auditor *auditService.Auditor, logger *zap.Logger) *Service {
	return &Service{db: db, auditor: auditor, logger: logger}
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	if s == nil || s.db == nil {
		return DefaultSettings(), nil
	}
	settings := DefaultSettings()
	err := s.db.QueryRowContext(ctx, `SELECT product_name, logo_url, favicon_url, primary_color, login_title, login_description, login_background_url, support_email, support_url, privacy_policy_url, terms_of_service_url, default_locale FROM instance_settings WHERE id = 1`).Scan(
		&settings.ProductName, &settings.LogoURL, &settings.FaviconURL, &settings.PrimaryColor, &settings.LoginTitle,
		&settings.LoginDescription, &settings.LoginBackgroundURL, &settings.SupportEmail, &settings.SupportURL,
		&settings.PrivacyPolicyURL, &settings.TermsOfServiceURL, &settings.DefaultLocale,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("get instance settings: %w", err)
	}
	return settings, nil
}

func (s *Service) Update(ctx context.Context, next Settings, actor string) (Settings, error) {
	if s == nil || s.db == nil {
		return Settings{}, fmt.Errorf("update instance settings: database unavailable")
	}
	next = normalize(next)
	if err := validate(next); err != nil {
		return Settings{}, err
	}
	previous, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO instance_settings (id, product_name, logo_url, favicon_url, primary_color, login_title, login_description, login_background_url, support_email, support_url, privacy_policy_url, terms_of_service_url, default_locale, updated_by_account_id, updated_at)
		VALUES (1, $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, NULLIF($13, '')::uuid, NOW())
		ON CONFLICT (id) DO UPDATE SET product_name=EXCLUDED.product_name, logo_url=EXCLUDED.logo_url, favicon_url=EXCLUDED.favicon_url, primary_color=EXCLUDED.primary_color, login_title=EXCLUDED.login_title, login_description=EXCLUDED.login_description, login_background_url=EXCLUDED.login_background_url, support_email=EXCLUDED.support_email, support_url=EXCLUDED.support_url, privacy_policy_url=EXCLUDED.privacy_policy_url, terms_of_service_url=EXCLUDED.terms_of_service_url, default_locale=EXCLUDED.default_locale, updated_by_account_id=EXCLUDED.updated_by_account_id, updated_at=NOW()`,
		next.ProductName, next.LogoURL, next.FaviconURL, next.PrimaryColor, next.LoginTitle, next.LoginDescription,
		next.LoginBackgroundURL, next.SupportEmail, next.SupportURL, next.PrivacyPolicyURL, next.TermsOfServiceURL, next.DefaultLocale, actor)
	if err != nil {
		return Settings{}, fmt.Errorf("update instance settings: %w", err)
	}
	if s.auditor != nil {
		oldJSON, _ := json.Marshal(previous)
		newJSON, _ := json.Marshal(next)
		auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord("instance.settings.update", actor, nil, json.RawMessage(`{"type":"instance_settings"}`), nil).WithOld(oldJSON).WithNew(newJSON))
	}
	return next, nil
}

func normalize(s Settings) Settings {
	s.ProductName = strings.TrimSpace(s.ProductName)
	s.LogoURL = strings.TrimSpace(s.LogoURL)
	s.FaviconURL = strings.TrimSpace(s.FaviconURL)
	s.PrimaryColor = strings.TrimSpace(s.PrimaryColor)
	s.LoginTitle = strings.TrimSpace(s.LoginTitle)
	s.LoginDescription = strings.TrimSpace(s.LoginDescription)
	s.LoginBackgroundURL = strings.TrimSpace(s.LoginBackgroundURL)
	s.SupportEmail = strings.TrimSpace(s.SupportEmail)
	s.SupportURL = strings.TrimSpace(s.SupportURL)
	s.PrivacyPolicyURL = strings.TrimSpace(s.PrivacyPolicyURL)
	s.TermsOfServiceURL = strings.TrimSpace(s.TermsOfServiceURL)
	s.DefaultLocale = strings.TrimSpace(s.DefaultLocale)
	return s
}

func validate(s Settings) error {
	if s.ProductName == "" || len(s.ProductName) > 120 || len(s.LoginTitle) > 160 || len(s.LoginDescription) > 500 {
		return fmt.Errorf("%w: invalid text length", ErrInvalidSettings)
	}
	if !hexColor.MatchString(s.PrimaryColor) {
		return fmt.Errorf("%w: primary_color must be a six-digit hex color", ErrInvalidSettings)
	}
	if s.DefaultLocale != "en" && s.DefaultLocale != "zh" {
		return fmt.Errorf("%w: default_locale must be en or zh", ErrInvalidSettings)
	}
	if s.SupportEmail != "" {
		if _, err := mail.ParseAddress(s.SupportEmail); err != nil || len(s.SupportEmail) > 254 {
			return fmt.Errorf("%w: invalid support_email", ErrInvalidSettings)
		}
	}
	for _, value := range []string{s.LogoURL, s.FaviconURL, s.LoginBackgroundURL, s.SupportURL, s.PrivacyPolicyURL, s.TermsOfServiceURL} {
		if err := validatePublicURL(value); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicURL(value string) error {
	if value == "" || strings.HasPrefix(value, "/") {
		return nil
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%w: URLs must be absolute http(s) URLs or root-relative paths", ErrInvalidSettings)
	}
	return nil
}
