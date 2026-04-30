# CalProxy Enhancement Implementation Guide

This guide provides a practical implementation plan and production-ready snippets for adding:

1. Trusted reverse-proxy real-IP handling
2. Public homepage with source aggregation
3. Updated `/` -> homepage -> login -> admin flow
4. Lightweight calendar widget UI

---

## 1) Step-by-step implementation plan

### Step 1 — Extend configuration
- Add a JSON config file (or env-backed JSON blob) with:
  - `trusted_proxies` (`[]string`, CIDR/IP entries)
  - `public_homepage.enabled` (`bool`)
  - `public_homepage.title` (`string`)
  - `public_homepage.sources` (`[]string` token ids or source names)
  - `public_homepage.require_auth` (`bool`, optional hardening toggle)
- Parse trusted CIDRs at startup and fail fast if invalid.

### Step 2 — Add trusted-proxy real-IP middleware
- Resolve remote peer from `r.RemoteAddr` first.
- Only parse `X-Forwarded-For` / `X-Real-IP` when the immediate peer is trusted.
- For `X-Forwarded-For`, walk from right-to-left and choose the first untrusted hop with a valid IP.
- Fallback to socket peer if header chain is invalid.
- Store resolved client IP in request context.

### Step 3 — Add public homepage API endpoint
- Add endpoint: `GET /api/public/homepage`.
- Return pre-aggregated, sanitized calendar items for configured homepage sources.
- Reuse existing cache layer and avoid exposing upstream URLs/API keys.

### Step 4 — Add homepage route and UI flow
- Route `/`:
  - if public homepage enabled and auth not required => serve `public/homepage.html`
  - else preserve current auth behavior
- Add `/admin` route for existing dashboard UI (`public/index.html`) behind auth.
- Keep `/login` flow intact; after success redirect to `/admin`.

### Step 5 — Build lightweight calendar widget renderer
- Server-side aggregate upcoming events (e.g. next 30 days).
- Render grouped by date in minimal HTML + CSS.
- Optional small JS for polling `/api/public/homepage` and live updates.

### Step 6 — Documentation and migration
- Update README with reverse-proxy setup examples (Nginx Proxy Manager, Cloudflare, Traefik).
- Add migration notes for route change (`/` now homepage, admin at `/admin`).

---

## 2) Go code snippet — reverse-proxy middleware (safe real client IP)

```go
package main

import (
    "context"
    "net"
    "net/http"
    "strings"
)

type ctxKey string

const clientIPKey ctxKey = "client_ip"

type proxyTrust struct {
    nets []*net.IPNet
    ips  map[string]struct{}
}

func newProxyTrust(entries []string) (*proxyTrust, error) {
    out := &proxyTrust{ips: map[string]struct{}{}}
    for _, raw := range entries {
        v := strings.TrimSpace(raw)
        if v == "" {
            continue
        }
        if ip := net.ParseIP(v); ip != nil {
            out.ips[ip.String()] = struct{}{}
            continue
        }
        _, cidr, err := net.ParseCIDR(v)
        if err != nil {
            return nil, err
        }
        out.nets = append(out.nets, cidr)
    }
    return out, nil
}

func (p *proxyTrust) trusted(ip net.IP) bool {
    if ip == nil {
        return false
    }
    if _, ok := p.ips[ip.String()]; ok {
        return true
    }
    for _, n := range p.nets {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}

func parseHostIP(remoteAddr string) net.IP {
    host, _, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        host = remoteAddr
    }
    return net.ParseIP(strings.TrimSpace(host))
}

func resolveClientIP(r *http.Request, trust *proxyTrust) string {
    peerIP := parseHostIP(r.RemoteAddr)
    if peerIP == nil {
        return ""
    }

    // Never trust forwarding headers from untrusted peers.
    if trust == nil || !trust.trusted(peerIP) {
        return peerIP.String()
    }

    // RFC style chain: client, proxy1, proxy2 ... (right-most is nearest proxy)
    xff := r.Header.Get("X-Forwarded-For")
    if xff != "" {
        parts := strings.Split(xff, ",")
        for i := len(parts) - 1; i >= 0; i-- {
            ip := net.ParseIP(strings.TrimSpace(parts[i]))
            if ip == nil {
                continue
            }
            if !trust.trusted(ip) {
                return ip.String()
            }
        }
    }

    if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
        if ip := net.ParseIP(xrip); ip != nil {
            return ip.String()
        }
    }

    return peerIP.String()
}

func realIPMiddleware(trust *proxyTrust, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := resolveClientIP(r, trust)
        ctx := context.WithValue(r.Context(), clientIPKey, ip)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func clientIPFromContext(r *http.Request) string {
    if v, ok := r.Context().Value(clientIPKey).(string); ok {
        return v
    }
    return ""
}
```

**Usage:** wrap your mux in `realIPMiddleware(...)` and use `clientIPFromContext(r)` in login/audit logs.

---

## 3) Go code snippet — homepage handler + aggregation

```go
type PublicHomepageConfig struct {
    Enabled     bool     `json:"enabled"`
    Title       string   `json:"title"`
    Sources     []string `json:"sources"`
    RequireAuth bool     `json:"require_auth"`
}

type PublicEvent struct {
    Source string    `json:"source"`
    Title  string    `json:"title"`
    Start  time.Time `json:"start"`
}

type PublicHomepageResponse struct {
    Title  string                 `json:"title"`
    Groups map[string][]PublicEvent `json:"groups"` // YYYY-MM-DD -> events
}

func (s *server) handlePublicHomepageData(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    // Optional: toggle auth requirement for homepage view
    if s.cfg.PublicHomepage.RequireAuth && !s.isAuthenticated(r) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    events := s.aggregateUpcomingHomepageEvents(30)
    groups := map[string][]PublicEvent{}
    for _, ev := range events {
        key := ev.Start.UTC().Format("2006-01-02")
        groups[key] = append(groups[key], ev)
    }

    writeJSON(w, http.StatusOK, PublicHomepageResponse{
        Title:  s.cfg.PublicHomepage.Title,
        Groups: groups,
    })
}
```

> Keep parser logic lightweight: extract DTSTART/SUMMARY from cached ICS text and bound results to a fixed window.

---

## 4) HTML/CSS layout — homepage + calendar (minimal JS)

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CalProxy Homepage</title>
  <style>
    :root { color-scheme: light dark; --bg:#0f1115; --panel:#171a21; --text:#e8ebf2; --muted:#9aa3b2; --acc:#6aa9ff; --line:#2a2f3a; }
    @media (prefers-color-scheme: light) {
      :root { --bg:#f7f9fc; --panel:#ffffff; --text:#111827; --muted:#5b6473; --acc:#1d4ed8; --line:#dce3ef; }
    }
    *{box-sizing:border-box} body{margin:0;font:14px/1.45 Inter,system-ui,sans-serif;background:var(--bg);color:var(--text)}
    .wrap{max-width:1100px;margin:0 auto;padding:20px}
    .top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px}
    .title{font-size:1.2rem;font-weight:700}
    .btn{border:1px solid var(--line);padding:8px 12px;border-radius:10px;text-decoration:none;color:var(--text)}
    .grid{display:grid;grid-template-columns:2fr 1fr;gap:16px}
    @media (max-width:900px){.grid{grid-template-columns:1fr}}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}
    .day{padding:10px 0;border-bottom:1px dashed var(--line)}
    .day:last-child{border-bottom:none}
    .date{font-weight:600;color:var(--acc);margin-bottom:6px}
    .item{display:flex;justify-content:space-between;gap:10px;padding:4px 0}
    .meta{color:var(--muted);font-size:.9em}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="top">
      <div class="title" id="homeTitle">My Media Dashboard</div>
      <a class="btn" href="/login">Login</a>
    </header>

    <section class="grid">
      <article class="card">
        <h2>Upcoming Calendar</h2>
        <div id="calendar">Loading…</div>
      </article>
      <aside class="card">
        <h3>Sources</h3>
        <div id="sources" class="meta">Configured by admin</div>
      </aside>
    </section>
  </div>

  <script>
    async function loadHomepage() {
      const res = await fetch('/api/public/homepage', { headers: { 'Accept': 'application/json' } });
      if (!res.ok) { document.getElementById('calendar').textContent = 'Unavailable'; return; }
      const data = await res.json();
      document.getElementById('homeTitle').textContent = data.title || 'CalProxy Homepage';

      const root = document.getElementById('calendar');
      root.innerHTML = '';
      const keys = Object.keys(data.groups || {}).sort();
      if (!keys.length) { root.textContent = 'No upcoming items.'; return; }

      for (const date of keys) {
        const day = document.createElement('div'); day.className = 'day';
        day.innerHTML = `<div class="date">${date}</div>`;
        for (const ev of data.groups[date]) {
          const row = document.createElement('div');
          row.className = 'item';
          row.innerHTML = `<span>${ev.title}</span><span class="meta">${ev.source}</span>`;
          day.appendChild(row);
        }
        root.appendChild(day);
      }
    }
    loadHomepage();
  </script>
</body>
</html>
```

---

## 5) Config struct updates

```go
type PublicHomepageConfig struct {
    Enabled     bool     `json:"enabled"`
    Title       string   `json:"title"`
    Sources     []string `json:"sources"`
    RequireAuth bool     `json:"require_auth"`
}

type ConfigFile struct {
    TrustedProxies []string             `json:"trusted_proxies"`
    PublicHomepage PublicHomepageConfig `json:"public_homepage"`
}

type config struct {
    Port           string
    PasswordHash   []byte
    DataFile       string
    CacheTTL       int
    TrustedProxies []string
    PublicHomepage PublicHomepageConfig
}
```

Recommended JSON:

```json
{
  "trusted_proxies": ["127.0.0.1", "172.16.0.0/12"],
  "public_homepage": {
    "enabled": true,
    "title": "My Media Dashboard",
    "sources": ["sonarr", "radarr"],
    "require_auth": false
  }
}
```

---

## 6) Security considerations

- **Header spoofing prevention**: never trust `X-Forwarded-For`/`X-Real-IP` unless immediate peer is trusted.
- **CIDR hygiene**: avoid broad ranges (`0.0.0.0/0`) in `trusted_proxies`.
- **Sensitive data isolation**: keep upstream URLs and API keys out of all public responses.
- **Response limits**: cap homepage events (e.g. max 300 events / 30 days) to avoid abuse.
- **Rate limiting (recommended)**: apply simple IP-based throttling to login and public API endpoints.
- **Session hardening**: set `Secure` cookie flag when running behind HTTPS termination.
- **Input validation**: validate source identifiers and reject unknown entries in homepage config.

---

## 7) Migration notes

Potentially breaking behavior when enabling homepage:

1. `/` now serves public homepage instead of admin UI.
2. Admin UI moves to `/admin`.
3. Login success redirect should move from `/` to `/admin`.
4. Automation or bookmarks pointing at old `/` admin should be updated.

Safe rollout recommendation:
- Release with feature flag (`public_homepage.enabled=false` default).
- Announce `/admin` route before turning homepage on.
- Add temporary redirect from `/dashboard` -> `/admin` if needed.
