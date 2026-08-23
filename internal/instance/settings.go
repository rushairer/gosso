// Package instance owns runtime, non-secret configuration for one GOSSO instance.
package instance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"

	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
)

var ErrInvalidSettings = errors.New("invalid instance settings")

type Settings struct {
	ProductName        string `json:"product_name"`
	LogoURL            string `json:"logo_url"`
	FaviconURL         string `json:"favicon_url"`
	LoginTitle         string `json:"login_title"`
	LoginDescription   string `json:"login_description"`
	LoginBackgroundURL string `json:"login_background_url"`
}

func DefaultSettings() Settings {
	return Settings{ProductName: "GOSSO"}
}

// PublicBranding excludes secret and operational configuration metadata.
type PublicBranding struct {
	ProductName        string `json:"product_name"`
	LogoURL            string `json:"logo_url"`
	FaviconURL         string `json:"favicon_url"`
	LoginTitle         string `json:"login_title"`
	LoginDescription   string `json:"login_description"`
	LoginBackgroundURL string `json:"login_background_url"`
}

func (s Settings) PublicBranding() PublicBranding {
	return PublicBranding{
		ProductName: s.ProductName, LogoURL: s.LogoURL, FaviconURL: s.FaviconURL,
		LoginTitle: s.LoginTitle, LoginDescription: s.LoginDescription, LoginBackgroundURL: s.LoginBackgroundURL,
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
	err := s.db.QueryRowContext(ctx, `SELECT product_name, logo_url, favicon_url, login_title, login_description, login_background_url FROM instance_settings WHERE id = 1`).Scan(
		&settings.ProductName, &settings.LogoURL, &settings.FaviconURL, &settings.LoginTitle,
		&settings.LoginDescription, &settings.LoginBackgroundURL,
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
	_, err = s.db.ExecContext(ctx, `INSERT INTO instance_settings (id, product_name, logo_url, favicon_url, login_title, login_description, login_background_url, updated_by_account_id, updated_at)
		VALUES (1, $1,$2,$3,$4,$5,$6, NULLIF($7, '')::uuid, NOW())
		ON CONFLICT (id) DO UPDATE SET product_name=EXCLUDED.product_name, logo_url=EXCLUDED.logo_url, favicon_url=EXCLUDED.favicon_url, login_title=EXCLUDED.login_title, login_description=EXCLUDED.login_description, login_background_url=EXCLUDED.login_background_url, updated_by_account_id=EXCLUDED.updated_by_account_id, updated_at=NOW()`,
		next.ProductName, next.LogoURL, next.FaviconURL, next.LoginTitle, next.LoginDescription, next.LoginBackgroundURL, actor)
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
	s.LoginTitle = strings.TrimSpace(s.LoginTitle)
	s.LoginDescription = strings.TrimSpace(s.LoginDescription)
	s.LoginBackgroundURL = strings.TrimSpace(s.LoginBackgroundURL)
	return s
}

func validate(s Settings) error {
	if s.ProductName == "" || len(s.ProductName) > 120 || len(s.LoginTitle) > 160 || len(s.LoginDescription) > 500 {
		return fmt.Errorf("%w: invalid text length", ErrInvalidSettings)
	}
	for _, value := range []string{s.LogoURL, s.FaviconURL, s.LoginBackgroundURL} {
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
