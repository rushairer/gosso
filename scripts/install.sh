#!/usr/bin/env bash
#
# gosso quick installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rushairer/gosso/main/scripts/install.sh | bash
#
# Environment variables:
#   GOSSO_VERSION   - Docker image tag (default: latest)
#   GOSSO_PORT      - Host port to expose (default: 8080)
#   GOSSO_INSTALL_DIR - Installation directory (default: $HOME/gosso)
#
set -euo pipefail

GOSSO_VERSION="${GOSSO_VERSION:-latest}"
GOSSO_PORT="${GOSSO_PORT:-8080}"
INSTALL_DIR="${GOSSO_INSTALL_DIR:-$HOME/gosso}"

# ── Helpers ──────────────────────────────────────────────

info()  { printf "\033[1;34m[INFO]\033[0m  %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m  %s\n" "$*"; }
error() { printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" >&2; }

generate_secret() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 32
    else
        # Fallback: read from /dev/urandom (macOS and Linux)
        head -c 32 /dev/urandom | xxd -p -c 64
    fi
}

# ── 1. Check prerequisites ──────────────────────────────

check_prerequisites() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        error "Docker is required but not installed."
        error "Install Docker: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null 2>&1 && ! docker-compose version &>/dev/null 2>&1; then
        error "Docker Compose is required. Please update Docker or install the compose plugin."
        missing=1
    fi

    if [ "$missing" -ne 0 ]; then
        exit 1
    fi

    info "Docker and Docker Compose found"
}

# ── 2. Create directory and generate config ─────────────

setup_install_dir() {
    if [ -d "$INSTALL_DIR" ]; then
        warn "Installation directory already exists: $INSTALL_DIR"
        warn "Existing configuration will not be overwritten."
        warn "To reinstall, remove the directory first: rm -rf $INSTALL_DIR"
        return
    fi

    mkdir -p "$INSTALL_DIR"
    info "Created installation directory: $INSTALL_DIR"
}

generate_config() {
    local env_file="$INSTALL_DIR/.env"

    if [ -f "$env_file" ]; then
        info "Configuration file already exists, skipping generation"
        return
    fi

    local db_pass
    db_pass="$(generate_secret)"
    local totp_key
    totp_key="$(generate_secret)"
    local verify_pepper
    verify_pepper="$(generate_secret)"

    cat > "$env_file" <<EOF
# gosso configuration
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Documentation: https://github.com/rushairer/gosso#configuration

# Server
GOSSO_WEB_SERVER_PORT=${GOSSO_PORT}
GOSSO_WEB_SERVER_PRODUCTION=true

# Issuer URL (update for production with your actual domain)
GOSSO_AUTH_ISSUER=https://localhost:${GOSSO_PORT}

# PostgreSQL
GOSSO_DATABASE_DRIVERS_POSTGRES_DSN=postgres://gosso:${db_pass}@db:5432/gosso?sslmode=disable

# Redis
GOSSO_REDIS_DSN=redis://redis:6379/0

# Security (auto-generated — keep these secret)
GOSSO_AUTH_TOTP_ENCRYPTION_KEY=${totp_key}
GOSSO_AUTH_VERIFY_HASH_PEPPER=${verify_pepper}

# PostgreSQL container password
POSTGRES_PASSWORD=${db_pass}
EOF

    chmod 600 "$env_file"
    info "Generated configuration: $env_file"
}

generate_compose_file() {
    local compose_file="$INSTALL_DIR/docker-compose.yml"

    if [ -f "$compose_file" ]; then
        info "docker-compose.yml already exists, skipping generation"
        return
    fi

    cat > "$compose_file" <<'COMPOSE'
services:
  gosso:
    image: ghcr.io/rushairer/gosso:${GOSSO_VERSION:-latest}
    container_name: gosso
    restart: unless-stopped
    ports:
      - "${GOSSO_PORT:-8080}:8080"
    env_file: .env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s

  db:
    image: postgres:16-alpine
    container_name: gosso-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: gosso
      POSTGRES_USER: gosso
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U gosso -d gosso"]
      interval: 5s
      timeout: 3s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: gosso-redis
    restart: unless-stopped
    command: redis-server --maxmemory 128mb --maxmemory-policy allkeys-lru
    volumes:
      - redisdata:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  pgdata:
  redisdata:
COMPOSE

    info "Generated docker-compose.yml"
}

# ── 3. Pull and start ───────────────────────────────────

start_services() {
    cd "$INSTALL_DIR"

    export GOSSO_VERSION GOSSO_PORT

    info "Pulling Docker images..."
    if docker compose version &>/dev/null 2>&1; then
        docker compose pull
        info "Starting services..."
        docker compose up -d
    else
        docker-compose pull
        info "Starting services..."
        docker-compose up -d
    fi
}

# ── 4. Wait for health check ────────────────────────────

wait_for_health() {
    info "Waiting for gosso to become healthy..."
    local max_attempts=30
    local attempt=0

    while [ "$attempt" -lt "$max_attempts" ]; do
        if curl -sf "http://localhost:${GOSSO_PORT}/health" >/dev/null 2>&1; then
            info "gosso is healthy!"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    warn "Health check timed out. gosso may still be starting up."
    warn "Check logs: cd $INSTALL_DIR && docker compose logs -f gosso"
}

# ── 5. Print success ────────────────────────────────────

print_success() {
    echo ""
    printf "\033[1;32m✓ gosso has been installed successfully!\033[0m\n"
    echo ""
    info "URL:           http://localhost:${GOSSO_PORT}"
    info "Install dir:   ${INSTALL_DIR}"
    info "Configuration: ${INSTALL_DIR}/.env"
    echo ""
    info "Next steps:"
    info "  1. Review and update ${INSTALL_DIR}/.env"
    info "  2. Configure TLS via reverse proxy for production"
    info "  3. Register your first admin account via the API"
    echo ""
    info "Manage:"
    info "  cd ${INSTALL_DIR}"
    info "  docker compose logs -f     # View logs"
    info "  docker compose restart     # Restart"
    info "  docker compose down        # Stop"
    echo ""
}

# ── Main ─────────────────────────────────────────────────

main() {
    echo ""
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║     gosso — Self-hosted SSO Server     ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo ""

    check_prerequisites
    setup_install_dir
    generate_config
    generate_compose_file
    start_services
    wait_for_health
    print_success
}

main "$@"
