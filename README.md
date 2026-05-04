# CalProxy

CalProxy is a lightweight security proxy for media calendar integrations.
It sits between public-facing clients and backend media automation services (Sonarr and Radarr) so sensitive credentials are never exposed directly.

```
welcal://calproxy:3000/cal/<token>                                ← public, safe to share
 ↓  fetched from and cached server-side
welcal://sonarr:8989/feed/v3/calendar/Sonarr.ics?apikey=SECRET   ← never sent to clients
welcal://sonarr:7979/feed/v3/calendar/Radarr.ics?apikey=SECRET   ← never sent to clients
```

---

## 1) Project Overview

CalProxy is designed to securely hide and proxy API-linked calendar access for media automation tools.

- Protects and abstracts API usage for **Radarr** and **Sonarr**.
- Acts as a **privacy and security layer** between public users and backend services.
- Users receive safe, shareable endpoints instead of direct API-bearing upstream URLs.

---

## 2) Important Notice (Read First)

> **100% of the code in this repository is AI-assisted generation.**
>
> **No official support, maintenance guarantees, or assistance will be provided.**
>
> **Use this project entirely at your own risk.**

This is a personal/experimental project shared for reference and learning.

---

## 3) Purpose / Why This Project Exists

This project exists to reduce credential exposure and improve control over media-service integrations.

Primary goals:

- Prevent direct exposure of sensitive API keys.
- Remove API keys from client-facing environments.
- Centralize and control API/feed access logic.
- Reduce accidental key leaks or misuse.

---

## 4) Problems Identified

CalProxy addresses the following common issues:

- API keys exposed in iCal feed URLs shared with calendar applications or clients.
- No dedicated secure proxy layer available for Sonarr/Radarr calendar feeds out of the box.
- Difficulty managing multiple service integrations securely in a single place.
- Risk of unauthorized API/feed usage through leaked or intercepted URLs.

---

## 5) Solutions Implemented

To solve these problems, CalProxy implements:

- A secure proxy layer that performs upstream requests server-side, hiding all credentials.
- Abstraction of direct client calls to Sonarr/Radarr behind randomized, opaque tokens.
- Centralized sensitive configuration handling — credentials remain on the server only.
- Structured request flow that rewrites or strips identifying information (e.g. `PRODID` headers) before returning responses.
- In-memory caching with ETag support to reduce upstream load and improve response times.

---

## 6) Features

### A) API/feed request forwarding
- Forwards public token-based requests to Sonarr/Radarr calendar feeds.
- Keeps upstream URLs and API keys private — never included in public responses.

### B) Secure authentication and header handling
- Admin interface protected by bcrypt-hashed password with 8-hour session TTL.
- Sensitive credentials handled entirely server-side; clients never see upstream context.

### C) Routing by service/source
- Each source (Sonarr instance, Radarr instance, or any iCal feed) gets its own token.
- Merge groups combine multiple sources into a single feed URL.
- Public pages allow slug-based calendar sharing with theme support.

### D) Operational visibility
- `/health` endpoint for container health checks and uptime monitoring.
- Admin stats endpoint (`/api/stats`) reports source count, cache usage, and TTL.
- Stale cache fallback — serves last known good feed if upstream is temporarily unreachable.
- Image proxying for Sonarr series posters and Radarr movie posters (no key exposure).
- 
### E) Enhanced thumbnail support (public view)
- Public calendar view includes **poster thumbnails** for both Sonarr (series) and Radarr (movies).
- Adds an **additional thumbnail slot per entry** to improve visual clarity when browsing schedule.
- Thumbnails are retrieved via the internal image proxy to prevent API key exposure.
- Supports:
  - Sonarr → series poster  
  - Radarr → movie poster 
- Optimized for caching (e.g. via Cloudflare) to reduce repeated upstream image requests.
- Graceful fallback if images are unavailable (no broken UI elements).
---

## 7) Usage Guide

### Step 1: Deploy the service

**Option A — Docker Compose (recommended)**

```bash
curl -O https://raw.githubusercontent.com/chr0mx/calproxy/main/docker-compose.yml
# Edit ADMIN_PASSWORD in the file before starting
docker compose up -d
```

The service will be available at `http://your-host:3456` (or whatever host port you set).

**Option B — Build from source**

```bash
git clone https://github.com/chr0mx/calproxy
cd calproxy
docker compose up -d --build
```

**Option C — Run locally without Docker**

```bash
DATA_FILE=./data/sources.json ADMIN_PASSWORD=yourpassword go run ./src/
```

---

### Step 2: Configure environment variables

Open `docker-compose.yml` and review the `environment` block. At minimum, set `ADMIN_PASSWORD`.

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `changeme` | Admin interface password — **must be changed** |
| `PORT` | `3000` | HTTP listen port inside the container |
| `DATA_FILE` | `/data/sources.json` | Path to the JSON persistence file |
| `CACHE_TTL` | `300` | Upstream feed cache duration in seconds |
| `PUBLIC_HOMEPAGE_ENABLED` | `true` | Set to `false` to disable the public homepage at `/` |
| `TRUSTED_PROXIES` | _(empty)_ | Comma-separated IPs/CIDRs allowed to supply `X-Real-IP` / `X-Forwarded-For` |
| `PUID` / `PGID` | _(unset)_ | Host UID/GID for bind-mount permission fixing (not needed for named volumes) |
| `APP_VERSION` / `APP_BRANCH` | _(build-time)_ | Optional override of version strings shown in the admin UI footer |

---

### Step 3: Start and access the admin interface

After starting the service, open `http://your-host:3456` in a browser.

Click **Login** and enter the `ADMIN_PASSWORD` value set in your compose file.

---

### Step 4: Connect Sonarr and Radarr

**Find the iCal feed URL in Sonarr:**
1. Open Sonarr → **Settings → General**
2. Scroll to **Calendar Feed**
3. Copy the iCal URL (it contains `?apikey=…`)

**Find the iCal feed URL in Radarr:**
1. Open Radarr → **Settings → General**
2. Scroll to **Calendar Feed**
3. Copy the iCal URL (it contains `?apikey=…`)

In the CalProxy admin dashboard, click **Add Source**, paste the upstream URL, give it a name, and save. CalProxy generates a tokenized public URL in the format:

```
/cal/<32-char-hex-token>
```

---

### Step 5: Share only proxy URLs

Use only the generated proxy endpoints with calendar clients:

```
webcal://your-domain/cal/<token>
```

Never share raw Sonarr/Radarr URLs that contain API keys.

If running CalProxy behind a reverse proxy with TLS (recommended), use your public domain with the `webcal://` scheme. For Nginx Proxy Manager, set `TRUSTED_PROXIES` so real client IPs are correctly identified:

```yaml
environment:
  TRUSTED_PROXIES: "172.16.0.0/12"
```

---

### Example flow

1. Add Sonarr/Radarr upstream feed URL in CalProxy admin.
2. CalProxy stores the upstream URL privately on server.
3. CalProxy returns a public token URL safe to share with calendar clients.
4. User subscribes to the CalProxy URL.
5. CalProxy fetches the upstream feed, rewrites identifying fields, and returns a clean calendar response.

---

### Public token behavior

| Condition | Response |
|-----------|----------|
| Valid, enabled token | `200 OK` — `text/calendar` feed |
| Unknown or disabled token | `404 Not Found` |
| Upstream unreachable, cache available | `200 OK` — stale cached feed served |
| Upstream unreachable, no cache | `503 Service Unavailable` |

---

## 8) Final Notes

- This repository is a personal/experimental project intended for learning and reference only.
- No support or maintenance commitment of any kind is provided.
