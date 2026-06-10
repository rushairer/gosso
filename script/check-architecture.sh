#!/bin/bash
# check-architecture.sh — Enforce architecture invariants from doc/ARCHITECTURE_INVARIANTS.md
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more violations found
#
# Usage:
#   ./script/check-architecture.sh          # run all checks
#   ./script/check-architecture.sh E3 L1    # run specific checks by invariant ID

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

VIOLATIONS=0
WARNINGS=0

# Track which checks to run; empty means run all
RUN_ONLY="${*:-}"

should_run() {
    if [ -z "$RUN_ONLY" ]; then
        return 0
    fi
    for id in $RUN_ONLY; do
        if [ "$id" = "$1" ]; then
            return 0
        fi
    done
    return 1
}

violation() {
    local id="$1"
    local file="$2"
    local line="$3"
    local message="$4"
    echo -e "${RED}VIOLATION [${id}]${NC} ${file}:${line} — ${message}"
    VIOLATIONS=$((VIOLATIONS + 1))
}

warning() {
    local id="$1"
    local file="$2"
    local line="$3"
    local message="$4"
    echo -e "${YELLOW}WARNING [${id}]${NC} ${file}:${line} — ${message}"
    WARNINGS=$((WARNINGS + 1))
}

pass() {
    local id="$1"
    local message="$2"
    echo -e "${GREEN}PASS [${id}]${NC} ${message}"
}

# ============================================================================
# E1: Sentinel errors — same error message must not appear in two packages
# ============================================================================
check_E1() {
    echo ""
    echo "=== E1: Sentinel Error Uniqueness ==="

    local data_file
    data_file=$(mktemp)
    local dup_list
    dup_list=$(mktemp)

    # Collect all errors.New("...") from non-test Go files: msg|dir|file:line
    grep -rn --include='*.go' 'errors\.New(' internal/ 2>/dev/null | grep -v '_test\.go:' | while IFS= read -r match; do
        file=$(echo "$match" | cut -d: -f1)
        lineno=$(echo "$match" | cut -d: -f2)
        msg=$(echo "$match" | sed -n 's/.*errors\.New(\s*"\([^"]*\)".*/\1/p')
        if [ -n "$msg" ]; then
            dir=$(dirname "$file")
            printf '%s|%s|%s:%s\n' "$msg" "$dir" "$file" "$lineno"
        fi
    done > "$data_file"

    # Find error messages that appear in more than one package directory
    if [ -s "$data_file" ]; then
        awk -F'|' '!seen[$1,$2]++ {msgs[$1]++} END {for (m in msgs) if (msgs[m]>1) print m}' "$data_file" > "$dup_list"
    fi

    local found=0
    if [ -s "$dup_list" ]; then
        found=1
        while IFS= read -r dup_msg; do
            [ -z "$dup_msg" ] && continue
            # Escape special regex chars in the message for grep
            escaped=$(printf '%s' "$dup_msg" | sed 's/[]\.*/[]/\\&/g')
            grep "^${escaped}|" "$data_file" | while IFS='|' read -r _ dir loc; do
                file=$(echo "$loc" | cut -d: -f1)
                lineno=$(echo "$loc" | cut -d: -f2)
                echo -e "${RED}VIOLATION [E1]${NC} ${file}:${lineno} — errors.New(\"${dup_msg}\") in ${dir} — define once in canonical package"
            done
        done < "$dup_list"
    fi

    rm -f "$data_file" "$dup_list"

    if [ "$found" -eq 0 ]; then
        pass "E1" "No duplicate sentinel errors found across packages"
    else
        VIOLATIONS=$((VIOLATIONS + found))
    fi
}

# ============================================================================
# E3: No inline errors.New() in controller files
# ============================================================================
check_E3() {
    echo ""
    echo "=== E3: No Inline errors.New() in Controllers ==="

    local found=0
    while IFS=: read -r file lineno content; do
        violation "E3" "$file" "$lineno" "Inline errors.New() in controller — use sentinel errors from service/domain"
        found=1
    done < <(grep -rn --include='*.go' 'errors\.New(' internal/*/controller/ 2>/dev/null | grep -v '_test\.go' || true)

    if [ "$found" -eq 0 ]; then
        pass "E3" "No inline errors.New() in controller files"
    fi
}

# ============================================================================
# C1: Every route in router/*.go must have rate limiting
# ============================================================================
check_C1() {
    echo ""
    echo "=== C1: Rate Limiting on All Routes ==="

    local found=0
    # Find all route registrations (GET, POST, PUT, DELETE, PATCH)
    while IFS=: read -r file lineno content; do
        # Check if the line contains a rate limiter reference
        if ! echo "$content" | grep -qiE 'rate|limit|throttle|RateLimiter|rateLimiter'; then
            warning "C1" "$file" "$lineno" "Route may be missing rate limiting: $(echo "$content" | sed 's/^[[:space:]]*//')"
            found=1
        fi
    done < <(grep -rn --include='*.go' -E '\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(' router/ 2>/dev/null | grep -v '_test\.go' || true)

    if [ "$found" -eq 0 ]; then
        pass "C1" "All routes appear to have rate limiting"
    fi
}

# ============================================================================
# L1: No .Sugar() calls in service/repository layers
# ============================================================================
check_L1() {
    echo ""
    echo "=== L1: Structured Logging (no Sugar) ==="

    local found=0
    # Check service and repository directories
    for dir in internal/*/service internal/*/repository; do
        [ -d "$dir" ] || continue
        while IFS=: read -r file lineno content; do
            violation "L1" "$file" "$lineno" "Use *zap.Logger instead of .Sugar() in service/repository layer"
            found=1
        done < <(grep -rn --include='*.go' '\.Sugar()' "$dir" 2>/dev/null | grep -v '_test\.go' || true)
    done

    if [ "$found" -eq 0 ]; then
        pass "L1" "No .Sugar() calls in service/repository layers"
    fi
}

# ============================================================================
# L2: No sensitive data patterns in logger calls
# ============================================================================
check_L2() {
    echo ""
    echo "=== L2: No Sensitive Data in Logs ==="

    local found=0
    # Check for common sensitive field names in zap.String/zap.Any etc.
    while IFS=: read -r file lineno content; do
        # Skip test files
        [[ "$file" == *_test.go ]] && continue
        warning "L2" "$file" "$lineno" "Possible sensitive data in log: $(echo "$content" | sed 's/^[[:space:]]*//' | head -c 80)"
        found=1
    done < <(grep -rn --include='*.go' -iE 'zap\.(String|Any|Reflect)\([^)]*"(password|secret|token|totp|csrf|authorization)"' internal/ middleware/ 2>/dev/null | grep -v '_test\.go' || true)

    if [ "$found" -eq 0 ]; then
        pass "L2" "No obvious sensitive data in log calls"
    fi
}

# ============================================================================
# R3: Repository files should not call BeginTx/Begin
# ============================================================================
check_R3() {
    echo ""
    echo "=== R3: Repositories Do Not Manage Transactions ==="

    local found=0
    for dir in internal/*/repository; do
        [ -d "$dir" ] || continue
        while IFS=: read -r file lineno content; do
            violation "R3" "$file" "$lineno" "Repository must not manage transactions — move BeginTx to service layer"
            found=1
        done < <(grep -rn --include='*.go' -E '\.(BeginTx|Begin)\(' "$dir" 2>/dev/null | grep -v '_test\.go' || true)
    done

    if [ "$found" -eq 0 ]; then
        pass "R3" "No transaction management in repository files"
    fi
}

# ============================================================================
# Main
# ============================================================================
echo "=========================================="
echo " gosso Architecture Invariant Checker"
echo "=========================================="

if should_run "E1"; then check_E1; fi
if should_run "E3"; then check_E3; fi
if should_run "C1"; then check_C1; fi
if should_run "L1"; then check_L1; fi
if should_run "L2"; then check_L2; fi
if should_run "R3"; then check_R3; fi

echo ""
echo "=========================================="
if [ "$VIOLATIONS" -gt 0 ]; then
    echo -e "${RED}Result: ${VIOLATIONS} violation(s), ${WARNINGS} warning(s)${NC}"
    echo "Violations must be fixed before merging."
    exit 1
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}Result: 0 violations, ${WARNINGS} warning(s)${NC}"
    echo "Warnings should be reviewed but do not block merging."
    exit 0
else
    echo -e "${GREEN}Result: All checks passed${NC}"
    exit 0
fi
