# CalProxy

A self-hostable reverse proxy that securely hides and proxies API keys for media automation tools — specifically **Radarr** and **Sonarr**.

CalProxy acts as a privacy and security layer between public-facing calendar clients and your backend media services. It exposes safe, shareable `webcal://` URLs without ever leaking upstream API keys, internal hostnames, or credentials.

```
GET /cal/<token>                                     ← public, safe to share
        ↓  fetched and cached server-side
http://sonarr:8989/feed/v3/calendar/Sonarr.ics?apikey=SECRET   ← never exposed to clients
```

---

## Important Notice

> **This project is 100% AI-assisted generated code.**
>
> No official support, maintenance guarantees, or assistance of any kind will be provided.
> **Use this project entirely at your own risk.**

---

## Purpose

The core goal of CalProxy is to prevent direct exposure of sensitive API keys in client-facing environments. By routing all requests through a secure proxy layer, it:

- Removes API keys from any URL that could be shared, logged, or cached by calendar clients
- Centralizes and controls all API access logic in one place
- Reduces the risk of accidental credential leaks or unauthorized API usage
- Provides a clean abstraction between public access and your private media infrastructure

---

## Problems This Project Solves

- API keys exposed in iCal feed URLs shared with calendar applications
- No secure proxy layer available for Sonarr/Radarr calendar feeds out of the box
- Difficulty managing multiple service integrations securely in a single place
- Risk of unauthorized API usage when feed URLs are shared or intercepted

---

## Solutions Implemented

- A proxy layer that intercepts and forwards calendar requests without exposing upstream credentials
- Abstraction of direct API calls to Radarr and Sonarr behind randomized, opaque tokens
- Centralized configuration handling for all sensitive credentials via environment variables
- Structured request handling that rewrites or strips identifying information (e.g., `PRODID` headers) before returning responses to clients
- In-memory caching with configurable TTL to reduce upstream load and improve response times

---

## Features

- **API request forwarding** — proxies iCal calendar feeds from Sonarr and Radarr to clients via token URLs
- **Secure credential handling** — upstream URLs and API keys are stored server-side and never returned in unauthenticated responses
- **Token-based routing** — each source is assigned a 128-bit cryptographically random hex token; tokens can be revoked and regenerated
- **Merge groups** — combine multiple calendar sources into a single feed URL
- **Image proxying** — proxies series and movie poster images without exposing upstream API keys
- **Admin dashboard** — browser-based UI for managing sources, merge groups, and public pages
- **Public pages** — slug-based calendar pages with theme support for sharing with others
- **Session authentication** — bcrypt-hashed admin password with 8-hour session TTL
- **ETag-based caching** — conditional upstream fetches with configurable TTL (default 300 seconds)
- **Docker-native** — multi-stage Docker build with PUID/PGID support for correct file permissions
- **Minimal dependencies** — written in Go with a single external dependency (`golang.org/x/crypto`)

---

## Usage Guide

### 1. Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/) installed
- A running Sonarr and/or Radarr instance accessible from the host running CalProxy

### 2. Get the Compose File

```bash
curl -O https://raw.githubusercontent.com/chr0mx/calproxy/main/docker-compose.yml
```

### 3. Configure Environment Variables

Open `docker-compose.yml` and set the following under `environment`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `changeme` | Password for the admin interface — **change this** |
| `PORT` | `3000` | HTTP listen port inside the container |
| `DATA_FILE` | `./data/sources.json` | Path to the JSON persistence file |
| `CACHE_TTL` | `300` | Upstream feed cache duration in seconds |
| `PUBLIC_HOMEPAGE_ENABLED` | `true` | Whether to serve a public homepage at `/` |
| `TRUSTED_PROXIES` | _(empty)_ | Comma-separated IPs/CIDRs allowed to supply `X-Real-IP` / `X-Forwarded-For` |

> API keys are **never** placed in environment variables. They are stored server-side inside the upstream URL of each source you configure via the admin UI.

### 4. Start the Service

```bash
docker compose up -d
```

The service will be available at `http://your-host:3000`.

### 5. Find Your Calendar Feed URLs

**Sonarr:**
1. Open Sonarr → **Settings → General**
2. Scroll to **Calendar Feed**
3. Copy the iCal feed URL (it contains `?apikey=…`)

**Radarr:**
1. Open Radarr → **Settings → General**
2. Scroll to **Calendar Feed**
3. Copy the iCal feed URL (it contains `?apikey=…`)

### 6. Add Sources in CalProxy

1. Navigate to `http://your-host:3000` and click **Login**
2. Enter the admin password configured in step 3
3. In the admin dashboard, click **Add Source**
4. Paste the upstream iCal URL (including the API key) into the **Upstream URL** field
5. Give the source a name and save

CalProxy generates a token URL in the format:

```
/cal/<32-char-hex-token>
```

This is the URL you share with calendar clients. The upstream URL and API key remain on the server.

### 7. Connect with Calendar Clients

Use the token URL with the `webcal://` scheme in any calendar application:

```
webcal://your-host:3000/cal/<token>
```

If you are running CalProxy behind a reverse proxy with TLS, use `https://` or `webcal://` with your public domain.

### 8. Optional — Reverse Proxy with NGINX Proxy Manager

1. Create a new **Proxy Host**
2. Set the domain to your public hostname (e.g., `calproxy.example.com`)
3. Forward to the container hostname and port (e.g., `calproxy:3000`)
4. Enable **Force SSL** and request a Let's Encrypt certificate

Set `TRUSTED_PROXIES` in your environment so CalProxy correctly identifies real client IPs:

```yaml
environment:
  TRUSTED_PROXIES: "172.16.0.0/12"
```

### 9. Build from Source (Optional)

```bash
git clone https://github.com/chr0mx/calproxy
cd calproxy
docker compose up -d --build
```

To run without Docker:

```bash
DATA_FILE=./data/sources.json ADMIN_PASSWORD=yourpassword go run ./src/
```

---

## Public Calendar Token Behavior

| Condition | Response |
|-----------|----------|
| Valid, enabled token | `200 OK` — `text/calendar` feed |
| Unknown or disabled token | `404 Not Found` |
| Upstream unreachable, cache available | `200 OK` — stale cached feed served |
| Upstream unreachable, no cache | `503 Service Unavailable` |

---

## Security Notes

- Upstream URLs (containing API keys) are **never** returned in unauthenticated API responses
- All `PRODID` fields in iCal output are rewritten to remove upstream app identity
- Tokens are generated using `crypto/rand` — 128 bits of entropy
- Admin routes are protected by session authentication with bcrypt-hashed passwords
- Upstream HTTP requests have a 10-second timeout to prevent resource exhaustion

---

## Final Notes

This is a personal and experimental project. No warranties are made regarding correctness, security, or fitness for any purpose. No support will be provided.

Do not commit or expose your `sources.json` data file, as it contains upstream URLs with API keys. Treat the data directory as sensitive.

Keep `ADMIN_PASSWORD` set to a strong value. The default `changeme` is intentionally insecure and must be replaced before any production or internet-facing use.
