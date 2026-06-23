-- 0018_logout_uris
-- OIDC Front-Channel and Back-Channel Logout URI support
-- See: https://openid.net/specs/openid-connect-frontchannel-1_0.html
-- See: https://openid.net/specs/openid-connect-backchannel-1_0.html

ALTER TABLE oauth2_clients
    ADD COLUMN frontchannel_logout_uri TEXT NOT NULL DEFAULT '',
    ADD COLUMN frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '',
    ADD COLUMN backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT false;
