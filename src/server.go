package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type config struct {
	Port               string
	AdminPassword      string
	DataFile           string
	CacheTTL           int
	PublicHomepageAuth bool
	TrustedProxiesRaw  string
	TrustedProxies     []string
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

	publicAuth := false
	if v := strings.ToLower(os.Getenv("PUBLIC_HOMEPAGE_REQUIRE_AUTH")); v == "1" || v == "true" || v == "yes" {
		publicAuth = true
	}
	trustedRaw := os.Getenv("TRUSTED_PROXIES")
	trusted := parseTrustedProxies(trustedRaw)

	return config{Port: port, AdminPassword: pass, DataFile: dataFile, CacheTTL: ttl, PublicHomepageAuth: publicAuth, TrustedProxiesRaw: trustedRaw, TrustedProxies: trusted}
}

func parseTrustedProxies(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

type Source struct {
	Token       string    `json:"token"`
	Name        string    `json:"name"`
	UpstreamURL string    `json:"upstreamUrl"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

type SourcePublic struct {
	Token       string    `json:"token"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

func (s Source) public() SourcePublic {
	return SourcePublic{Token: s.Token, Name: s.Name, Description: s.Description, Enabled: s.Enabled, CreatedAt: s.CreatedAt}
}

type store struct {
	mu       sync.RWMutex
	sources  map[string]Source
	dataFile string
}

func newStore(dataFile string) *store {
	s := &store{sources: map[string]Source{}, dataFile: dataFile}
	s.load()
	return s
}
func (s *store) load() {
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return
	}
	var list []Source
	if err := json.Unmarshal(data, &list); err != nil {
		return
	}
	for _, src := range list {
		s.sources[src.Token] = src
	}
}
func (s *store) save() {
	list := make([]Source, 0, len(s.sources))
	for _, src := range s.sources {
		list = append(list, src)
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	_ = os.MkdirAll(filepath.Dir(s.dataFile), 0755)
	_ = os.WriteFile(s.dataFile, data, 0644)
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

type cacheEntry struct {
	data, etag string
	fetchedAt  time.Time
}
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

func newCache(ttl int) *cache {
	return &cache{entries: map[string]cacheEntry{}, ttl: time.Duration(ttl) * time.Second}
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
func (c *cache) evict(token string) { c.mu.Lock(); defer c.mu.Unlock(); delete(c.entries, token) }
func (c *cache) fresh(token string) (cacheEntry, bool) {
	e, ok := c.get(token)
	if !ok {
		return e, false
	}
	return e, time.Since(e.fetchedAt) < c.ttl
}
func (c *cache) count() int { c.mu.RLock(); defer c.mu.RUnlock(); return len(c.entries) }

var prodidRe = regexp.MustCompile(`(?m)^PRODID:.*$`)

func sanitizeICal(body string) string {
	return prodidRe.ReplaceAllString(body, "PRODID:-//CalProxy//CalProxy//EN")
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func fetchUpstream(src Source, etag string) (string, string, bool, error) {
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

func randomToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type trustedProxyChecker struct {
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

func newTrustedProxyChecker(entries []string) *trustedProxyChecker {
	c := &trustedProxyChecker{ips: map[string]struct{}{}}
	for _, e := range entries {
		if ip := net.ParseIP(e); ip != nil {
			c.ips[ip.String()] = struct{}{}
			continue
		}
		if _, netw, err := net.ParseCIDR(e); err == nil {
			c.cidrs = append(c.cidrs, netw)
		}
	}
	return c
}
func (t *trustedProxyChecker) isTrusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if _, ok := t.ips[ip.String()]; ok {
		return true
	}
	for _, n := range t.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveRealIP(r *http.Request, checker *trustedProxyChecker) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(strings.TrimSpace(host))
	if !checker.isTrusted(remoteIP) {
		return strings.TrimSpace(host)
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			candidate := net.ParseIP(strings.TrimSpace(part))
			if candidate != nil {
				return candidate.String()
			}
		}
	}
	if xrip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xrip != nil {
		return xrip.String()
	}
	if remoteIP != nil {
		return remoteIP.String()
	}
	return strings.TrimSpace(host)
}

type server struct {
	cfg     config
	db      *store
	cache   *cache
	trusted *trustedProxyChecker
}

func newServer(cfg config) *server {
	return &server{cfg: cfg, db: newStore(cfg.DataFile), cache: newCache(cfg.CacheTTL), trusted: newTrustedProxyChecker(cfg.TrustedProxies)}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cal/", s.handleCal)
	mux.HandleFunc("/api/public/homepage", s.handlePublicHomepageData)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/admin", basicAuth(s.cfg.AdminPassword, s.handleUI))
	mux.HandleFunc("/api/sources", basicAuth(s.cfg.AdminPassword, s.handleSources))
	mux.HandleFunc("/api/sources/", basicAuth(s.cfg.AdminPassword, s.handleSourcesToken))
	mux.HandleFunc("/api/stats", basicAuth(s.cfg.AdminPassword, s.handleStats))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realIP := resolveRealIP(r, s.trusted)
		w.Header().Set("X-Real-Client-IP", realIP)
		mux.ServeHTTP(w, r)
	})
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.cfg.PublicHomepageAuth {
		basicAuth(s.cfg.AdminPassword, s.handleUI)(w, r)
		return
	}
	http.ServeFile(w, r, "public/homepage.html")
}

func (s *server) handlePublicHomepageData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	all := s.db.list()
	enabled := make([]SourcePublic, 0)
	for _, src := range all {
		if src.Enabled {
			enabled = append(enabled, src.public())
		}
	}
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].Name < enabled[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"generatedAt": time.Now().UTC(), "sources": enabled})
}

func (s *server) handleCal(w http.ResponseWriter, r *http.Request) { /* unchanged */
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/cal/")
	_ = s.clientIP(r)
	if token == "" {
		http.NotFound(w, r)
		return
	}
	src, ok := s.db.get(token)
	if !ok || !src.Enabled {
		http.NotFound(w, r)
		return
	}
	if entry, fresh := s.cache.fresh(token); fresh {
		serveICal(w, src.Name, s.cfg.CacheTTL, entry.data)
		return
	}
	stale, hasStale := s.cache.get(token)
	storedEtag := ""
	if hasStale {
		storedEtag = stale.etag
	}
	body, newEtag, notModified, err := fetchUpstream(src, storedEtag)
	if err != nil {
		if hasStale {
			serveICal(w, src.Name, s.cfg.CacheTTL, stale.data)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if notModified {
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

// admin handlers same
func (s *server) handleSources(w http.ResponseWriter, r *http.Request) { /* ... */
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
			Name, UpstreamURL, Description string
			Enabled                        *bool
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Name == "" || body.UpstreamURL == "" {
			http.Error(w, "name and upstreamUrl are required", http.StatusBadRequest)
			return
		}
		token, _ := randomToken()
		enabled := true
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		src := Source{Token: token, Name: body.Name, UpstreamURL: body.UpstreamURL, Description: body.Description, Enabled: enabled, CreatedAt: time.Now().UTC()}
		s.db.set(src)
		writeJSON(w, http.StatusCreated, src)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
func (s *server) handleSourcesToken(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/sources/")
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
			Name, UpstreamURL, Description *string
			Enabled                        *bool
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
		s.cache.evict(token)
		writeJSON(w, http.StatusOK, src)
	case http.MethodDelete:
		if !s.db.delete(token) {
			http.NotFound(w, r)
			return
		}
		s.cache.evict(token)
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
	writeJSON(w, http.StatusOK, map[string]any{"sources": len(s.db.list()), "cached": s.cache.count(), "cacheTtl": s.cfg.CacheTTL, "trustedProxies": s.cfg.TrustedProxies})
}
func (s *server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	if !s.cfg.PublicHomepage.Enabled {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "public/index.html")
}

func main() {
	log.SetFlags(0)
	cfg := loadConfig()
	srv := newServer(cfg)
	hs := &http.Server{Addr: ":" + cfg.Port, Handler: srv.routes(), ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	}()
	log.Printf("[CalProxy] listening on :%s", cfg.Port)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("fatal: %v", err)
	}
}
