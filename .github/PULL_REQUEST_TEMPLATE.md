## What does this PR do?

<!-- A brief description of the change and its motivation. -->

## Related issues

<!-- Link related issues: Fixes #123, Closes #456 -->

## Checklist

- [ ] `go mod tidy` -- no stray dependencies
- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] `make build` succeeds
- [ ] New/changed behavior is covered by tests

### Security checklist (if applicable)

- [ ] No secrets, tokens, or passwords in the diff
- [ ] `redirect_uri` validated with exact match (if changed)
- [ ] `state` / `nonce` parameters validated (if OAuth/OIDC flow changed)
- [ ] JWT verification checks `iss`, `aud`, `exp`, `alg` (if token handling changed)
- [ ] Audit log covers new auth events (if applicable)
- [ ] Sensitive data is not logged

## Additional notes

<!-- Anything reviewers should watch out for: migration steps, breaking changes, known limitations. -->
