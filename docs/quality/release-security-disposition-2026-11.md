# Gosso v1.7.0 security scan disposition

The standalone gosec v2.27.1 scan of the release preparation found 21 reports. Previously CI used `-no-fail`; the release train removes that option. No scanner category is disabled. The former category-wide golangci-lint exclusions for G101/G124/G115/G118/G304/G706 are removed.

Reviewed source-level decisions:

| Rule / count | Source boundary | Disposition |
| --- | --- | --- |
| G115 / 1 | account/domain/credential.go | `parseArgon2idHash` checks decoded hash length 16..64 before uint32 conversion; bounded-hash regressions remain authoritative |
| G115 / 1 | cmd/gosso/web.go | ConfigManager validates log level -1..5 before int8 conversion; configuration rejection tests cover invalid levels |
| G404 / 1 | utility/security.go | Random jitter affects timing padding only, never token/key/nonce generation; retain the existing non-cryptographic jitter contract |
| G101 / 1 | config/config_manager.go | Public localhost development DSN; production configuration explicitly rejects this value |
| G101 / 1 | auth/service/auth_session.go | Redis lock namespace, not a refresh token |
| G101 / 6 | audit/domain/actions.go | Public audit event identifiers, not credential values |
| G101 / 1 | account/repository/credential_repository_impl.go | Parameterized SQL projection and column names, no embedded credential values |
| G124 / 4 | auth/controller helpers and social cookies | Explicit HttpOnly + SameSite=Lax; Secure is `!Debug` from web_modules.go and production rejects Debug. Local HTTP development remains supported |
| G304 / 3 | config secret and token signing-key readers | Operator-controlled deployment paths, never HTTP request input; retain existing G703 trust-boundary annotations and explicitly cover G304 |
| G706 / 2 | script/parse-config.go | Remove executable-name and environment interpolation from usage/missing-environment diagnostics; use fixed messages |

These narrow `#nosec` annotations document actual data-flow limits; they do not certify a deployment or justify weakening future findings. Cookie safety still depends on validated production configuration. A production target, final image scans, immutable digest/signature verification and integration acceptance remain separate release gates.

Local validation: `GOWORK=off GOTOOLCHAIN=go1.26.10 go run github.com/securego/gosec/v2/cmd/gosec@v2.27.1 -fmt json -out /tmp/gosso-gosec-reviewed.json ./...` returned zero unsuppressed findings. The exact committed SHA must still pass hosted CI before tagging.

The lint-embedded gosec v2.29.0 additionally reported twenty test-only sites after removal of blanket exclusions: ten synthetic credential/configuration fixtures (G101), nine incoming request-cookie fixtures (G124, which cannot carry response security attributes), and one t.TempDir signing-key fixture (G304). They are annotated at those sites only; no runtime scanner rule is excluded.
