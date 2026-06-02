ALTER TABLE oauth2_clients ADD COLUMN post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]';
