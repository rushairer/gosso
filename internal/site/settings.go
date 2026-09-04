// Package site owns runtime, non-secret configuration for the GOSSO site.
package site

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"

	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
)

var ErrInvalidSettings = errors.New("invalid site settings")

const maxLoginBackgroundSourceBytes = 8 * 1024 * 1024

type Settings struct {
	ProductName        string `json:"product_name"`
	LogoURL            string `json:"logo_url"`
	FaviconURL         string `json:"favicon_url"`
	LoginTitle         string `json:"login_title"`
	LoginDescription   string `json:"login_description"`
	LoginBackgroundURL string `json:"login_background_url"`
}

func DefaultSettings() Settings {
	return Settings{
		ProductName: "GOSSO", FaviconURL: "/favicon.svg", LoginTitle: "GOSSO",
		LoginDescription: "Identity & Access Provider Console",
	}
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
	return PublicBranding(s)
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
	err := s.db.QueryRowContext(ctx, `SELECT product_name, logo_url, favicon_url, login_title, login_description, login_background_url FROM site_settings WHERE id = 1`).Scan(
		&settings.ProductName, &settings.LogoURL, &settings.FaviconURL, &settings.LoginTitle,
		&settings.LoginDescription, &settings.LoginBackgroundURL,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("get site settings: %w", err)
	}
	return settings, nil
}

func (s *Service) Update(ctx context.Context, next Settings, actor string) (Settings, error) {
	if s == nil || s.db == nil {
		return Settings{}, fmt.Errorf("update site settings: database unavailable")
	}
	next = normalize(next)
	if err := validate(next); err != nil {
		return Settings{}, err
	}
	previous, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO site_settings (id, product_name, logo_url, favicon_url, login_title, login_description, login_background_url, updated_by_account_id, updated_at)
		VALUES (1, $1,$2,$3,$4,$5,$6, NULLIF($7, '')::uuid, NOW())
		ON CONFLICT (id) DO UPDATE SET product_name=EXCLUDED.product_name, logo_url=EXCLUDED.logo_url, favicon_url=EXCLUDED.favicon_url, login_title=EXCLUDED.login_title, login_description=EXCLUDED.login_description, login_background_url=EXCLUDED.login_background_url, updated_by_account_id=EXCLUDED.updated_by_account_id, updated_at=NOW()`,
		next.ProductName, next.LogoURL, next.FaviconURL, next.LoginTitle, next.LoginDescription, next.LoginBackgroundURL, actor)
	if err != nil {
		return Settings{}, fmt.Errorf("update site settings: %w", err)
	}
	if s.auditor != nil {
		oldJSON, _ := json.Marshal(auditSnapshot(previous))
		newJSON, _ := json.Marshal(auditSnapshot(next))
		auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord("site.settings.update", actor, nil, json.RawMessage(`{"type":"site_settings"}`), nil).WithOld(oldJSON).WithNew(newJSON))
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
	for _, value := range []string{s.LogoURL, s.FaviconURL} {
		if err := validatePublicURL(value); err != nil {
			return err
		}
	}
	return validateLoginBackgroundSource(s.LoginBackgroundURL)
}

func validateLoginBackgroundSource(value string) error {
	if len(value) > maxLoginBackgroundSourceBytes {
		return fmt.Errorf("%w: login background source exceeds 8 MiB", ErrInvalidSettings)
	}
	if strings.HasPrefix(strings.ToLower(value), "data:") {
		return validateLoginBackgroundDataURL(value)
	}
	return validatePublicURL(value)
}

func validateLoginBackgroundDataURL(value string) error {
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return fmt.Errorf("%w: malformed login background data URL", ErrInvalidSettings)
	}

	metadata := value[len("data:"):comma]
	parts := strings.Split(metadata, ";")
	if len(parts) != 2 || !strings.EqualFold(parts[1], "base64") {
		return fmt.Errorf("%w: login background data URL must use base64 encoding", ErrInvalidSettings)
	}

	mimeType := strings.ToLower(parts[0])
	switch mimeType {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
	default:
		return fmt.Errorf("%w: unsupported login background image type", ErrInvalidSettings)
	}

	payload := value[comma+1:]
	if payload == "" {
		return fmt.Errorf("%w: empty login background image", ErrInvalidSettings)
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(payload)
	}
	if err != nil {
		return fmt.Errorf("%w: invalid login background base64 data", ErrInvalidSettings)
	}
	if !matchesImageType(mimeType, decoded) {
		return fmt.Errorf("%w: login background image data does not match its MIME type", ErrInvalidSettings)
	}
	return nil
}

func matchesImageType(mimeType string, data []byte) bool {
	switch mimeType {
	case "image/png":
		return bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	case "image/jpeg":
		return bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff})
	case "image/gif":
		return bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))
	case "image/webp":
		return len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP"))
	default:
		return false
	}
}

func auditSnapshot(settings Settings) Settings {
	if strings.HasPrefix(strings.ToLower(settings.LoginBackgroundURL), "data:image/") {
		if comma := strings.IndexByte(settings.LoginBackgroundURL, ','); comma >= 0 {
			settings.LoginBackgroundURL = settings.LoginBackgroundURL[:comma+1] + "[base64 image omitted]"
		} else {
			settings.LoginBackgroundURL = "[base64 image omitted]"
		}
	}
	return settings
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
