package instance

import "testing"

func TestDefaultSettingsAreValid(t *testing.T) {
	if err := validate(DefaultSettings()); err != nil {
		t.Fatalf("default settings must validate: %v", err)
	}
}

func TestValidateRejectsUnsafeSettings(t *testing.T) {
	cases := []Settings{
		{ProductName: "GOSSO", PrimaryColor: "blue", DefaultLocale: "en"},
		{ProductName: "GOSSO", PrimaryColor: "#3b82f6", DefaultLocale: "fr"},
		{ProductName: "GOSSO", PrimaryColor: "#3b82f6", DefaultLocale: "en", SupportURL: "javascript:alert(1)"},
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
	if err := validate(settings); err != nil {
		t.Fatalf("expected safe URLs to validate: %v", err)
	}
}
