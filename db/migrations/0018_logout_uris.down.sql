-- Revert 0018: remove OIDC Front-Channel and Back-Channel Logout URI columns

ALTER TABLE oauth2_clients
    DROP COLUMN IF EXISTS frontchannel_logout_uri,
    DROP COLUMN IF EXISTS frontchannel_logout_session_required,
    DROP COLUMN IF EXISTS backchannel_logout_uri,
    DROP COLUMN IF EXISTS backchannel_logout_session_required;
