# CalProxy

A self-hostable reverse proxy that exposes safe, shareable `webcal://` URLs for
Sonarr and Radarr calendar feeds — without leaking upstream URLs, API keys, or
internal hostnames to calendar clients.

```
GET /cal/<32-char-hex-token>        ← public, safe to share
        ↓  fetched + cached server-side
http://sonarr:8989/feed/...?apikey=SECRET   ← never sent to clients
```

---

## Quick start

### Option A — pre-built image (recommended)

```bash
# 1. Download the compose file
curl -O https://raw.githubusercontent.com/chr0mx/calproxy/main/docker-compose.yml

# 2. Set your admin password
#    Linux/macOS:
sed -i 's/ADMIN_PASSWORD: changeme/ADMIN_PASSWORD: yourpassword/' docker-compose.yml
#    Or just open the file and edit ADMIN_PASSWORD manually.

# 3. Start
docker compose up -d
```

The image is pulled automatically from `ghcr.io/chr0mx/calproxy:latest`.  
To pin to a specific release use a tag instead: `ghcr.io/chr0mx/calproxy:1.0.0`.

### Option B — build from source

```bash
git clone https://github.com/chr0mx/calproxy
cd calproxy
# Replace the image: line with build: . in docker-compose.yml, then:
docker compose up -d --build
```

Open `http://your-host:3456` and log in with any username and the password you set.

---

## Finding the calendar URL

### Sonarr
1. Open Sonarr → **Settings → General**
2. Scroll to **Calendar Feed**
3. Copy the **iCal Feed** URL (includes `?apikey=…`)

### Radarr
1. Open Radarr → **Settings → General**
2. Scroll to **Calendar Feed**
3. Copy the **iCal Feed** URL (includes `?apikey=…`)

Paste the copied URL into CalProxy as the **Upstream URL** when adding a source.
CalProxy will proxy it via a token URL that is safe to share.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP listen port |
| `ADMIN_PASSWORD` | `changeme` | Password for HTTP Basic Auth (any username accepted) |
| `DATA_FILE` | `./data/sources.json` | Path to the JSON persistence file |
| `CACHE_TTL` | `300` | How long to cache upstream feeds, in seconds |

---

## Nginx Proxy Manager setup

1. In NPM, create a new **Proxy Host**
2. **Domain Names**: `calproxy.example.com`
3. **Forward Hostname/IP**: `calproxy` (container name on the `proxy` network)
4. **Forward Port**: `3000`
5. Enable **Block Common Exploits** and **Websockets Support**
6. Under **SSL**, request a Let's Encrypt certificate and enable **Force SSL**
7. Save — CalProxy is now reachable at `https://calproxy.example.com`

Calendar clients should use `webcal://calproxy.example.com/cal/<token>`.

---

## Admin API reference

All admin endpoints require HTTP Basic Auth (any username, `ADMIN_PASSWORD`).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sources` | List all sources — `upstreamUrl` is **never** included |
| `GET` | `/api/sources/:token` | Get one source including `upstreamUrl` (for editing) |
| `POST` | `/api/sources` | Create a source; token is auto-generated |
| `PUT` | `/api/sources/:token` | Update `name`, `upstreamUrl`, `description`, or `enabled` |
| `DELETE` | `/api/sources/:token` | Delete source and evict its cache entry |
| `POST` | `/api/sources/:token/refresh` | Purge cached feed for one source |
| `GET` | `/api/stats` | Returns `{ sources, cached, cacheTtl }` |

### Source schema

```json
{
  "token":       "a1b2c3d4e5f6...",
  "name":        "Sonarr TV",
  "upstreamUrl": "http://sonarr:8989/feed/v3/calendar/Sonarr.ics?apikey=SECRET",
  "description": "TV show air dates",
  "enabled":     true,
  "createdAt":   "2026-04-29T00:00:00.000Z"
}
```

### Example: create a source

```bash
curl -u admin:changeme \
  -X POST http://localhost:3456/api/sources \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Sonarr TV",
    "upstreamUrl": "http://sonarr:8989/feed/v3/calendar/Sonarr.ics?apikey=SECRET",
    "description": "TV show air dates"
  }'
```

---

## Public endpoint

```
GET /cal/:token
```

- Returns `Content-Type: text/calendar; charset=utf-8`
- Sets `Cache-Control: public, max-age=<CACHE_TTL>`
- Rewrites `PRODID:` to hide upstream app identity
- Returns `404` for unknown or disabled tokens
- Returns `503` if the upstream is unreachable and no stale cache exists
- Serves stale cache on upstream failure if a previous successful fetch exists

---

## Security

- `upstreamUrl` never appears in unauthenticated responses
- `PRODID` is always rewritten in the iCal output
- Tokens are 128-bit cryptographically random hex strings
- HTTP Basic Auth protects all admin routes and the admin UI
- Upstream fetch timeout: 10 seconds

---

## Development

```bash
# Run locally (no Docker)
DATA_FILE=./data/sources.json ADMIN_PASSWORD=secret go run ./src/

# Build binary
go build -o calproxy ./src/

# Build Docker image
docker build -t calproxy .
```

## Enhancement guide

See `IMPLEMENTATION_GUIDE.md` for a complete implementation plan and production-oriented snippets for trusted reverse-proxy IP handling, public homepage flow, and calendar widget UI.
