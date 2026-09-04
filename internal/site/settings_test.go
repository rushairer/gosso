package site

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDefaultSettingsAreValid(t *testing.T) {
	if err := validate(DefaultSettings()); err != nil {
		t.Fatalf("default settings must validate: %v", err)
	}
}

func TestValidateRejectsUnsafeSettings(t *testing.T) {
	cases := []Settings{
		{ProductName: ""},
		{ProductName: "GOSSO", LogoURL: "javascript:alert(1)"},
		{ProductName: "GOSSO", LoginBackgroundURL: "javascript:alert(1)"},
	}
	for _, settings := range cases {
		if err := validate(settings); err == nil {
			t.Fatalf("expected invalid settings to fail: %#v", settings)
		}
	}
}

func TestValidateAllowsRootRelativeAndHTTPSURLs(t *testing.T) {
	settings := DefaultSettings()
	settings.LogoURL = "/assets/logo.svg"
	settings.FaviconURL = "https://cdn.example.test/favicon.svg"
	settings.LoginBackgroundURL = "https://cdn.example.test/background.webp"
	if err := validate(settings); err != nil {
		t.Fatalf("expected safe URLs to validate: %v", err)
	}
}

func TestValidateAllowsBase64LoginBackgroundImages(t *testing.T) {
	cases := []struct {
		name     string
		mimeType string
		data     []byte
	}{
		{name: "png", mimeType: "image/png", data: []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}},
		{name: "jpeg", mimeType: "image/jpeg", data: []byte{0xff, 0xd8, 0xff, 0xe0}},
		{name: "gif", mimeType: "image/gif", data: []byte("GIF89a")},
		{name: "webp", mimeType: "image/webp", data: []byte{'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P'}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			settings := DefaultSettings()
			settings.LoginBackgroundURL = "data:" + test.mimeType + ";base64," + base64.StdEncoding.EncodeToString(test.data)
			if err := validate(settings); err != nil {
				t.Fatalf("expected %s data URL to validate: %v", test.mimeType, err)
			}
		})
	}
}

func TestValidateRejectsInvalidBase64LoginBackgroundImages(t *testing.T) {
	cases := []string{
		"data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
		"data:text/html;base64,PGgxPm5vPC9oMT4=",
		"data:image/png,not-base64",
		"data:image/png;base64,not-base64!",
		"data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("GIF89a")),
	}
	for _, value := range cases {
		settings := DefaultSettings()
		settings.LoginBackgroundURL = value
		if err := validate(settings); err == nil {
			t.Fatalf("expected invalid data URL to fail: %q", value)
		}
	}
}

func TestValidateRejectsOversizedLoginBackgroundSource(t *testing.T) {
	settings := DefaultSettings()
	settings.LoginBackgroundURL = "data:image/png;base64," + strings.Repeat("A", maxLoginBackgroundSourceBytes)
	if err := validate(settings); err == nil {
		t.Fatal("expected oversized login background source to fail")
	}
}

func TestAuditSnapshotOmitsBase64Payload(t *testing.T) {
	settings := DefaultSettings()
	settings.LoginBackgroundURL = "data:image/png;base64,iVBORw0KGgo="
	got := auditSnapshot(settings).LoginBackgroundURL
	if got != "data:image/png;base64,[base64 image omitted]" {
		t.Fatalf("audit background = %q", got)
	}
}

func TestSettingsPublicBrandingPreservesPublicFields(t *testing.T) {
	settings := Settings{
		ProductName:        "GOSSO",
		LogoURL:            "/logo.svg",
		FaviconURL:         "/favicon.svg",
		LoginTitle:         "Sign in",
		LoginDescription:   "Use your account",
		LoginBackgroundURL: "https://cdn.example.test/background.webp",
	}

	if got := settings.PublicBranding(); got != PublicBranding(settings) {
		t.Fatalf("public branding = %#v, want %#v", got, PublicBranding(settings))
	}
}

func TestServiceWithoutDatabaseUsesSafeDefaults(t *testing.T) {
	service := NewService(nil, nil, nil)
	got, err := service.Get(context.Background())
	if err != nil {
		t.Fatalf("get default settings: %v", err)
	}
	if got != DefaultSettings() {
		t.Fatalf("settings = %#v, want %#v", got, DefaultSettings())
	}
	if _, err := service.Update(context.Background(), DefaultSettings(), ""); err == nil {
		t.Fatal("expected update without a database to fail")
	}
}

func TestNormalizeTrimsEveryPublicField(t *testing.T) {
	got := normalize(Settings{
		ProductName:        " GOSSO ",
		LogoURL:            " /logo.svg ",
		FaviconURL:         " /favicon.svg ",
		LoginTitle:         " Sign in ",
		LoginDescription:   " Use your account ",
		LoginBackgroundURL: " /background.webp ",
	})
	want := Settings{
		ProductName:        "GOSSO",
		LogoURL:            "/logo.svg",
		FaviconURL:         "/favicon.svg",
		LoginTitle:         "Sign in",
		LoginDescription:   "Use your account",
		LoginBackgroundURL: "/background.webp",
	}
	if got != want {
		t.Fatalf("normalized settings = %#v, want %#v", got, want)
	}
}

func TestServiceGetReturnsStoredSettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sql mock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	want := Settings{
		ProductName:        "Acme",
		LogoURL:            "/logo.svg",
		FaviconURL:         "/favicon.svg",
		LoginTitle:         "Sign in",
		LoginDescription:   "Welcome",
		LoginBackgroundURL: "/background.webp",
	}
	mock.ExpectQuery("SELECT product_name").WillReturnRows(
		sqlmock.NewRows([]string{"product_name", "logo_url", "favicon_url", "login_title", "login_description", "login_background_url"}).
			AddRow(want.ProductName, want.LogoURL, want.FaviconURL, want.LoginTitle, want.LoginDescription, want.LoginBackgroundURL),
	)

	got, err := NewService(db, nil, nil).Get(context.Background())
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	if got != want {
		t.Fatalf("settings = %#v, want %#v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}

func TestServiceGetHandlesMissingAndFailedRows(t *testing.T) {
	for _, test := range []struct {
		name      string
		queryErr  error
		wantError bool
	}{
		{name: "missing", queryErr: sql.ErrNoRows},
		{name: "database error", queryErr: errors.New("database unavailable"), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("create sql mock: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			mock.ExpectQuery("SELECT product_name").WillReturnError(test.queryErr)

			got, err := NewService(db, nil, nil).Get(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
			if !test.wantError && got != DefaultSettings() {
				t.Fatalf("settings = %#v, want defaults", got)
			}
		})
	}
}

func TestServiceUpdateNormalizesAndPersistsSettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("create sql mock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	current := DefaultSettings()
	mock.ExpectQuery("SELECT product_name").WillReturnRows(
		sqlmock.NewRows([]string{"product_name", "logo_url", "favicon_url", "login_title", "login_description", "login_background_url"}).
			AddRow(current.ProductName, current.LogoURL, current.FaviconURL, current.LoginTitle, current.LoginDescription, current.LoginBackgroundURL),
	)
	background := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	mock.ExpectExec("INSERT INTO site_settings").
		WithArgs("Acme", "/logo.svg", "", "Sign in", "Welcome", background, "00000000-0000-0000-0000-000000000001").
		WillReturnResult(sqlmock.NewResult(1, 1))

	got, err := NewService(db, nil, nil).Update(context.Background(), Settings{
		ProductName: " Acme ", LogoURL: " /logo.svg ", LoginTitle: " Sign in ", LoginDescription: " Welcome ", LoginBackgroundURL: background,
	}, "00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("update settings: %v", err)
	}
	if got.ProductName != "Acme" || got.LogoURL != "/logo.svg" || got.LoginBackgroundURL != background {
		t.Fatalf("updated settings were not normalized/persisted: %#v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database expectations: %v", err)
	}
}
