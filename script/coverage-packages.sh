#!/bin/sh
# Print packages included in the unit-test coverage gate.
#
# The full test suite still runs for every package. This list intentionally
# excludes wiring-only packages, test helpers, and Redis/TCP-heavy packages.
# Security/protocol packages such as router, middleware, token service, and
# OAuth2/OIDC services remain in the gate.

set -eu

: "${GOCACHE:=${TMPDIR:-/tmp}/gosso-go-build-cache}"
export GOCACHE
mkdir -p "$GOCACHE"

stderr_file=$(mktemp)
if ! packages=$(GOFLAGS="${GOFLAGS:-} -mod=readonly" go list ./... 2>"$stderr_file"); then
	cat "$stderr_file" >&2
	rm -f "$stderr_file"
	exit 1
fi
rm -f "$stderr_file"

printf '%s\n' "$packages" |
	grep -Ev '/(cmd|deploy|docs|examples|script|tests)(/|$)' |
	grep -Ev '/internal/(account|auth|oauth2|oidc|testutil)$' |
	grep -Ev '/internal/cache$'
