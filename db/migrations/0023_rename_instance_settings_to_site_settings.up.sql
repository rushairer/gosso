ALTER TABLE instance_settings RENAME TO site_settings;

COMMENT ON TABLE site_settings IS 'Singleton runtime configuration for public identity-provider site branding.';
