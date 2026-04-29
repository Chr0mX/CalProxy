# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o calproxy ./src/

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

# su-exec: tiny setuid helper to drop from root to the app user after fixing
# bind-mount ownership in the entrypoint. getent is part of musl libc on Alpine.
RUN apk add --no-cache su-exec \
 && addgroup -S calproxy && adduser -S -G calproxy calproxy

WORKDIR /app

COPY --from=builder /build/calproxy .
COPY public/ ./public/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

ENV DATA_FILE=/data/sources.json

# Entrypoint runs as root only long enough to mkdir + chown the data dir,
# then drops privileges via su-exec.
ENTRYPOINT ["./entrypoint.sh"]
