# CalProxy

CalProxy is a lightweight security proxy for media calendar/API-style integrations.
It sits between public-facing clients and backend media automation services (Sonarr and Radarr) so sensitive credentials are not exposed directly.

## 1) Project Overview

CalProxy is designed to securely hide and proxy API-linked access for media automation tools.

- It protects and abstracts API usage patterns for **Radarr** and **Sonarr**.
- It acts as a **privacy and security layer** between public consumers and backend services.
- Clients receive safe, shareable proxy endpoints instead of direct credential-bearing upstream URLs.

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

- API keys exposed in frontend clients or public configuration files.
- No dedicated secure proxy layer for Sonarr/Radarr access.
- Difficulty managing multiple service integrations safely.
- Risk of unauthorized API/feed usage through leaked URLs.

---

## 5) Solutions Implemented

To solve these problems, CalProxy implements:

- A secure proxy layer that performs upstream requests server-side.
- Abstraction of direct client calls to Sonarr/Radarr endpoints.
- Centralized sensitive configuration handling (credentials remain on server).
- Structured request flow to prevent secret leakage in public responses.

---

## 6) Features / Function Breakdown

### A) API/feed request forwarding
- Forwards public token-based requests to backend services.
- Keeps upstream URLs and sensitive credentials private.

### B) Secure authentication/header handling
- Protects administrative operations with authentication.
- Handles sensitive headers/credential context server-side.

### C) Routing by service/source
- Supports routing logic across different configured media sources.
- Allows separate source definitions (for Sonarr, Radarr, or multiple instances).

### D) Configuration-driven setup
- Uses environment variables for runtime behavior.
- Keeps security-sensitive settings centralized and easier to audit.

### E) Optional operational visibility
- Includes operational endpoints/flows for status and cache behavior.
- Logging/debug-style visibility can be used during local troubleshooting (deployment-dependent).

---

## 7) Usage Guide

## Step 1: Deploy the service

### Option A — Docker Compose (recommended)
```bash
curl -O https://raw.githubusercontent.com/chr0mx/calproxy/main/docker-compose.yml
# Edit ADMIN_PASSWORD before starting
docker compose up -d
```

### Option B — Build/run locally
```bash
git clone https://github.com/chr0mx/calproxy
cd calproxy
docker compose up -d --build
```

## Step 2: Configure environment variables

At minimum, review/set:

- `ADMIN_PASSWORD` (required; use a strong value)
- `PORT`
- `DATA_FILE`
- `CACHE_TTL`
- `TRUSTED_PROXIES` (if running behind reverse proxy)

Example:

```yaml
environment:
  PORT: "3000"
  ADMIN_PASSWORD: "replace-with-strong-password"
  DATA_FILE: "./data/sources.json"
  CACHE_TTL: "300"
  TRUSTED_PROXIES: "127.0.0.1,172.16.0.0/12"
```

## Step 3: Store API keys securely

- Do **not** place API keys in frontend code, client apps, or public docs.
- Add upstream Sonarr/Radarr feed URLs only in the authenticated admin area.
- Treat those upstream URLs as secrets because they may contain keys.

## Step 4: Start and access the admin interface

- Start service and open `http://<host>:3456` (or your mapped port/domain).
- Sign in through the admin login.

## Step 5: Connect Sonarr and Radarr

- Copy each iCal/feed URL from Sonarr/Radarr settings.
- Create a source in CalProxy with name + upstream URL.
- CalProxy generates a tokenized public URL.

## Step 6: Share only proxy URLs

Use only generated proxy endpoints, for example:

```text
webcal://your-domain/cal/<token>
```

Never share raw Sonarr/Radarr URLs that contain API keys.

## Example high-level flow

1. Admin adds Sonarr/Radarr upstream feed in CalProxy.
2. CalProxy stores the upstream URL privately.
3. Client subscribes to CalProxy token URL.
4. CalProxy fetches/caches upstream data and returns sanitized calendar output.

---

## 8) Final Notes

- Keep all credentials server-side only.
- Do not expose real API keys in examples, screenshots, or config snippets.
- This repository is a personal/experimental project intended for learning/reference.
- No support or maintenance commitment is provided.
