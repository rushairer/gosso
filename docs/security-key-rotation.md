# Signing-Key Rotation Runbook

Gosso keeps one active RSA private key for signing and may retain historical **public** keys for verification/JWKS overlap.

## Prepare

1. Generate the next RSA private key (3072 bits recommended) and choose a new unique `kid`.
2. Export the current active key's public key to a PEM file.
3. Configure `GOUNO_AUTH_PREVIOUS_PUBLIC_KEY_PATH` to that old public PEM and `GOUNO_AUTH_PREVIOUS_KEY_ID` to the old `kid`.

## Activate

Deploy the new private key as `auth.private_key_path` and set `auth.key_id` to the new `kid`. On startup Gosso loads the retained public key, signs only with the new private key, validates access tokens by `kid`, and publishes both keys through JWKS.

The in-process `KeyService.ActivateKey` API provides the same atomic active-to-retained transition for runtime integrations: the old active public key is retained automatically and the `(private key, kid)` signing snapshot changes atomically.

## Retire

After the overlap window is safely beyond every token or accepted logout hint that can reference the old key, remove the previous-key environment variables and redeploy, or call `RetireKey(oldKid)` in a runtime integration. Never reuse a `kid` for different key material.

Only public key material should be retained for historical verification. The old private key should not remain mounted after activation unless an external rollback procedure explicitly requires it.
