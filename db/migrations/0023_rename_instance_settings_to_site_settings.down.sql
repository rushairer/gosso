ALTER TABLE site_settings RENAME TO instance_settings;

COMMENT ON TABLE instance_settings IS 'Singleton runtime configuration for public identity-provider branding.';
