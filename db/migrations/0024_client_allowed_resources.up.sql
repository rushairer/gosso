-- 0024_client_allowed_resources
-- RFC 8707 Resource Indicators support for OAuth2 clients
ALTER TABLE oauth2_clients
    ADD COLUMN allowed_resources JSONB NOT NULL DEFAULT '[]'::jsonb;
