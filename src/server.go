// CalProxy — self-hostable webcal reverse proxy for Sonarr/Radarr.
// Chosen stack: Go — single binary, zero runtime deps, stdlib HTTP is sufficient for
// this workload, and multi-stage Docker build produces a tiny image.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	Port          string
	AdminPassword string
	DataFile      string
	CacheTTL      int // seconds
}

func loadConfig() config {
	ttl := 300
	if v := os.Getenv("CACHE_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = n
		}
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	pass := os.Getenv("ADMIN_PASSWORD")
	if pass == "" {
		pass = "changeme"
	}
	dataFile := os.Getenv("DATA_FILE")
	if dataFile == "" {
		dataFile = "./data/sources.json"
	}
	return config{Port: port, AdminPassword: pass, DataFile: dataFile, CacheTTL: ttl}
}

// ── Persistence ───────────────────────────────────────────────────────────────

type Source struct {
	Token       string    `json:"token"`
	Name        string    `json:"name"`
	UpstreamURL string    `json:"upstreamUrl"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

// SourcePublic is Source without upstreamUrl, used in list responses.
type SourcePublic struct {
	Token       string    `json:"token"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

func (s Source) public() SourcePublic {
	return SourcePublic{
		Token:       s.Token,
		Name:        s.Name,
		Description: s.Description,
		Enabled:     s.Enabled,
		CreatedAt:   s.CreatedAt,
	}
}

type store struct {
	mu       sync.RWMutex
	sources  map[string]Source // keyed by token
	dataFile string
}

func newStore(dataFile string) *store {
	s := &store{sources: make(map[string]Source), dataFile: dataFile}
	s.load()
	return s
}

func (s *store) load() {
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		// Missing file is expected on first run.
		return
	}
	var list []Source
	if err := json.Unmarshal(data, &list); err != nil {
		log.Printf("[CalProxy] WARN: could not parse %s, starting with empty sources: %v", s.dataFile, err)
		return
	}
	for _, src := range list {
		s.sources[src.Token] = src
	}
	log.Printf("[CalProxy] loaded %d source(s) from %s", len(s.sources), s.dataFile)
}

func (s *store) save() {
	list := make([]Source, 0, len(s.sources))
	for _, src := range s.sources {
		list = append(list, src)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		log.Printf("[CalProxy] ERROR: marshal sources: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.dataFile), 0755); err != nil {
		log.Printf("[CalProxy] ERROR: create data dir: %v", err)
		return
	}
	if err := os.WriteFile(s.dataFile, data, 0644); err != nil {
		log.Printf("[CalProxy] ERROR: write sources: %v", err)
	}
}

func (s *store) list() []Source {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Source, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src)
	}
	return out
}

func (s *store) get(token string) (Source, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src, ok := s.sources[token]
	return src, ok
}

func (s *store) set(src Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources[src.Token] = src
	s.save()
}

func (s *store) delete(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sources[token]; !ok {
		return false
	}
	delete(s.sources, token)
	s.save()
	return true
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func basicAuth(password string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="CalProxy Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ── Caching ───────────────────────────────────────────────────────────────────

type cacheEntry struct {
	data      string
	etag      string
	fetchedAt time.Time
}

type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

func newCache(ttl int) *cache {
	return &cache{
		entries: make(map[string]cacheEntry),
		ttl:     time.Duration(ttl) * time.Second,
	}
}

func (c *cache) get(token string) (cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[token]
	return e, ok
}

func (c *cache) set(token string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[token] = e
}

func (c *cache) evict(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, token)
}

func (c *cache) fresh(token string) (cacheEntry, bool) {
	e, ok := c.get(token)
	if !ok {
		return e, false
	}
	return e, time.Since(e.fetchedAt) < c.ttl
}

func (c *cache) count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ── iCal sanitisation ─────────────────────────────────────────────────────────

var prodidRe = regexp.MustCompile(`(?m)^PRODID:.*$`)

func sanitizeICal(body string) string {
	return prodidRe.ReplaceAllString(body, "PRODID:-//CalProxy//CalProxy//EN")
}

// ── Upstream fetch ────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 10 * time.Second}

func fetchUpstream(src Source, etag string) (body string, newEtag string, notModified bool, err error) {
	req, err := http.NewRequest(http.MethodGet, src.UpstreamURL, nil)
	if err != nil {
		return "", "", false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return "", etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", false, fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", false, err
	}
	return string(raw), resp.Header.Get("ETag"), false, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func tokenFromPath(r *http.Request, prefix string) string {
	return strings.TrimPrefix(r.URL.Path, prefix)
}

// ── Server ────────────────────────────────────────────────────────────────────

type server struct {
	cfg   config
	db    *store
	cache *cache
}

func newServer(cfg config) *server {
	return &server{
		cfg:   cfg,
		db:    newStore(cfg.DataFile),
		cache: newCache(cfg.CacheTTL),
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// Public calendar endpoint.
	mux.HandleFunc("/cal/", s.handleCal)

	// Admin UI — basic auth protected.
	mux.HandleFunc("/", basicAuth(s.cfg.AdminPassword, s.handleUI))

	// Admin API — basic auth protected.
	mux.HandleFunc("/api/sources", basicAuth(s.cfg.AdminPassword, s.handleSources))
	mux.HandleFunc("/api/sources/", basicAuth(s.cfg.AdminPassword, s.handleSourcesToken))
	mux.HandleFunc("/api/stats", basicAuth(s.cfg.AdminPassword, s.handleStats))

	return mux
}

// ── Public routes ─────────────────────────────────────────────────────────────

func (s *server) handleCal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/cal/")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	src, ok := s.db.get(token)
	if !ok || !src.Enabled {
		http.NotFound(w, r)
		return
	}

	// Try fresh cache first.
	if entry, fresh := s.cache.fresh(token); fresh {
		serveICal(w, src.Name, s.cfg.CacheTTL, entry.data)
		return
	}

	// Fetch from upstream; use ETag if we have a stale entry.
	stale, hasStale := s.cache.get(token)
	var storedEtag string
	if hasStale {
		storedEtag = stale.etag
	}

	body, newEtag, notModified, err := fetchUpstream(src, storedEtag)
	if err != nil {
		log.Printf("[CalProxy] upstream error for token %s: %v", token, err)
		if hasStale {
			log.Printf("[CalProxy] serving stale cache for token %s", token)
			serveICal(w, src.Name, s.cfg.CacheTTL, stale.data)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	if notModified {
		// Upstream confirmed our cached copy is still valid — refresh timestamp.
		s.cache.set(token, cacheEntry{data: stale.data, etag: storedEtag, fetchedAt: time.Now()})
		serveICal(w, src.Name, s.cfg.CacheTTL, stale.data)
		return
	}

	sanitized := sanitizeICal(body)
	s.cache.set(token, cacheEntry{data: sanitized, etag: newEtag, fetchedAt: time.Now()})
	serveICal(w, src.Name, s.cfg.CacheTTL, sanitized)
}

func serveICal(w http.ResponseWriter, name string, ttl int, body string) {
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", ttl))
	w.Header().Set("X-WR-CALNAME", name)
	_, _ = io.WriteString(w, body)
}

// ── Admin routes ──────────────────────────────────────────────────────────────

// handleSources handles /api/sources (GET list, POST create).
func (s *server) handleSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		all := s.db.list()
		pub := make([]SourcePublic, 0, len(all))
		for _, src := range all {
			pub = append(pub, src.public())
		}
		writeJSON(w, http.StatusOK, pub)

	case http.MethodPost:
		var body struct {
			Name        string `json:"name"`
			UpstreamURL string `json:"upstreamUrl"`
			Description string `json:"description"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Name == "" || body.UpstreamURL == "" {
			http.Error(w, "name and upstreamUrl are required", http.StatusBadRequest)
			return
		}
		token, err := randomToken()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		enabled := true
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		src := Source{
			Token:       token,
			Name:        body.Name,
			UpstreamURL: body.UpstreamURL,
			Description: body.Description,
			Enabled:     enabled,
			CreatedAt:   time.Now().UTC(),
		}
		s.db.set(src)
		log.Printf("[CalProxy] created source %q (token %s)", src.Name, src.Token)
		writeJSON(w, http.StatusCreated, src)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleSourcesToken handles /api/sources/:token and sub-paths.
func (s *server) handleSourcesToken(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/sources/")

	// POST /api/sources/:token/refresh
	if strings.HasSuffix(rest, "/refresh") {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimSuffix(rest, "/refresh")
		if _, ok := s.db.get(token); !ok {
			http.NotFound(w, r)
			return
		}
		s.cache.evict(token)
		log.Printf("[CalProxy] cache purged for token %s", token)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	token := rest
	switch r.Method {
	case http.MethodGet:
		src, ok := s.db.get(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, src)

	case http.MethodPut:
		src, ok := s.db.get(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Name        *string `json:"name"`
			UpstreamURL *string `json:"upstreamUrl"`
			Description *string `json:"description"`
			Enabled     *bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Name != nil {
			src.Name = *body.Name
		}
		if body.UpstreamURL != nil {
			src.UpstreamURL = *body.UpstreamURL
		}
		if body.Description != nil {
			src.Description = *body.Description
		}
		if body.Enabled != nil {
			src.Enabled = *body.Enabled
		}
		s.db.set(src)
		s.cache.evict(token) // invalidate after update
		log.Printf("[CalProxy] updated source %s", token)
		writeJSON(w, http.StatusOK, src)

	case http.MethodDelete:
		if !s.db.delete(token) {
			http.NotFound(w, r)
			return
		}
		s.cache.evict(token)
		log.Printf("[CalProxy] deleted source %s", token)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources":  len(s.db.list()),
		"cached":   s.cache.count(),
		"cacheTtl": s.cfg.CacheTTL,
	})
}

// handleUI serves the admin SPA from the embedded public/index.html.
func (s *server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "public/index.html")
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(0) // timestamps are added by the prefix
	cfg := loadConfig()

	srv := newServer(cfg)
	hs := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      srv.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Println("[CalProxy] shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.Shutdown(ctx); err != nil {
			log.Printf("[CalProxy] shutdown error: %v", err)
		}
	}()

	log.Printf("[CalProxy] listening on :%s  (TTL=%ds  data=%s)", cfg.Port, cfg.CacheTTL, cfg.DataFile)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[CalProxy] fatal: %v", err)
	}
	log.Println("[CalProxy] stopped")
}
