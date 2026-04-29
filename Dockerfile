# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o calproxy ./src/

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN addgroup -S calproxy && adduser -S -G calproxy calproxy

WORKDIR /app

COPY --from=builder /build/calproxy .
COPY public/ ./public/

RUN mkdir -p /data && chown calproxy:calproxy /data

USER calproxy

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/stats || exit 1

ENV DATA_FILE=/data/sources.json

ENTRYPOINT ["./calproxy"]
