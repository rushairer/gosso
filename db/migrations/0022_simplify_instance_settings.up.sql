ALTER TABLE instance_settings
    DROP COLUMN IF EXISTS primary_color,
    DROP COLUMN IF EXISTS support_email,
    DROP COLUMN IF EXISTS support_url,
    DROP COLUMN IF EXISTS privacy_policy_url,
    DROP COLUMN IF EXISTS terms_of_service_url,
    DROP COLUMN IF EXISTS default_locale;
