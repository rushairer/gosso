ALTER TABLE site_settings
    DROP CONSTRAINT IF EXISTS site_settings_login_background_url_length_check;

COMMENT ON COLUMN site_settings.login_background_url IS NULL;
