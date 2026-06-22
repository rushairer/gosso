# Build stage
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /build/bin/gosso \
    ./cmd

# Runtime stage
FROM alpine:3.22.0

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -S gosso && adduser -S gosso -G gosso

WORKDIR /app

COPY --from=builder /build/bin/gosso /app/gosso
COPY --from=builder /build/config/production.yaml /app/config/production.yaml
COPY --from=builder /build/db/migrations /app/db/migrations
COPY --from=builder /build/script/entrypoint.sh /app/entrypoint.sh

RUN chown -R gosso:gosso /app && chmod 0755 /app/entrypoint.sh

USER gosso

EXPOSE 8080

# Explicitly request SIGTERM for graceful shutdown (Go handles SIGTERM to drain connections).
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD wget -qO- http://localhost:8080/readiness || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["web", "-e", "production"]
