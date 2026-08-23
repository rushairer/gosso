CREATE TABLE IF NOT EXISTS instance_settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    product_name VARCHAR(120) NOT NULL DEFAULT 'GOSSO',
    logo_url TEXT NOT NULL DEFAULT '',
    favicon_url TEXT NOT NULL DEFAULT '',
    primary_color VARCHAR(7) NOT NULL DEFAULT '#3b82f6',
    login_title VARCHAR(160) NOT NULL DEFAULT '',
    login_description VARCHAR(500) NOT NULL DEFAULT '',
    login_background_url TEXT NOT NULL DEFAULT '',
    support_email VARCHAR(254) NOT NULL DEFAULT '',
    support_url TEXT NOT NULL DEFAULT '',
    privacy_policy_url TEXT NOT NULL DEFAULT '',
    terms_of_service_url TEXT NOT NULL DEFAULT '',
    default_locale VARCHAR(10) NOT NULL DEFAULT 'en',
    updated_by_account_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE instance_settings IS 'Singleton runtime configuration for public identity-provider branding.';
