-- 0013_oauth2_consents.down.sql

DROP TRIGGER IF EXISTS update_oauth2_consents_updated_at ON oauth2_consents;
DROP TABLE IF EXISTS oauth2_consents;
