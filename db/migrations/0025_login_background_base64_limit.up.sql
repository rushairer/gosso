ALTER TABLE site_settings
    DROP CONSTRAINT IF EXISTS site_settings_login_background_url_length_check;

ALTER TABLE site_settings
    ADD CONSTRAINT site_settings_login_background_url_length_check
    CHECK (octet_length(login_background_url) <= 8388608);

COMMENT ON COLUMN site_settings.login_background_url IS
    'Login background URL/root-relative path or validated base64 image data URL, maximum 8 MiB encoded source.';
