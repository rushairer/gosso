# MFA step-up API migration

`POST /api/v1/auth/mfa/step-up` is deprecated. It remains available only to
non-browser clients presenting an access token whose `aud` includes
`urn:gouno:gosso-api`.

Browser applications and BFFs must start a new OIDC authorization-code request
at `/oauth2/authorize` with PKCE S256, `nonce`, `state`, and
`acr_values=urn:gouno:aal2`. Operations requiring a fresh authentication event
also send `max_age=600`. When the current GOSSO session cannot satisfy those
parameters, GOSSO displays its own authentication and MFA UI and then resumes
the original authorization request.

Relying parties must validate the returned ID Token signature, issuer, audience,
expiration, nonce, `acr`, `amr`, and `auth_time`. Do not accept absent claims or
synthesize fallback values.
