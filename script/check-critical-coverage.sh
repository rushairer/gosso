#!/bin/sh
# Enforce package-level coverage floors for security/protocol-critical services.
# These floors track the current package-local coverage baseline and should be
# raised as focused tests are added.

set -eu

: "${GOCACHE:=${TMPDIR:-/tmp}/gosso-go-build-cache}"
export GOCACHE
mkdir -p "$GOCACHE"

check_package() {
	pkg="$1"
	min="$2"

	output=$(go test -cover "$pkg")
	printf '%s\n' "$output"

	cov=$(printf '%s\n' "$output" | awk '/coverage:/ {gsub("%", "", $5); print $5; exit}')
	if [ -z "$cov" ]; then
		echo "Could not determine coverage for $pkg" >&2
		exit 1
	fi

	awk "BEGIN {exit !($cov >= $min)}" || {
		echo "Coverage for $pkg is ${cov}%, below ${min}%" >&2
		exit 1
	}
}

check_package ./internal/auth/service "${AUTH_SERVICE_COVERAGE_MIN:-34.9}"
check_package ./internal/oauth2/service "${OAUTH2_SERVICE_COVERAGE_MIN:-22.3}"
check_package ./internal/token/service "${TOKEN_SERVICE_COVERAGE_MIN:-19.5}"
check_package ./internal/oidc/service "${OIDC_SERVICE_COVERAGE_MIN:-31.7}"
check_package ./internal/session/service "${SESSION_SERVICE_COVERAGE_MIN:-6.6}"
