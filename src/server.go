// CalProxy — self-hostable webcal reverse proxy for Sonarr/Radarr.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	Port           string
	PasswordHash   []byte
	DataFile       string
	CacheTTL       int
	TrustedProxies []netip.Prefix
	PublicHomepage bool
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

	publicHomepage := true
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("PUBLIC_HOMEPAGE_ENABLED"))); v == "false" || v == "0" || v == "no" {
		publicHomepage = false
	}

	trusted := parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("[CalProxy] FATAL: cannot hash admin password: %v", err)
	}

	// Allow runtime override of build-time version vars via env vars.
	if v := os.Getenv("APP_VERSION"); v != "" {
		appVersion = v
	}
	if v := os.Getenv("APP_BRANCH"); v != "" {
		appBranch = v
	}

	return config{Port: port, PasswordHash: hash, DataFile: dataFile, CacheTTL: ttl, TrustedProxies: trusted, PublicHomepage: publicHomepage}
}

func parseTrustedProxies(raw string) []netip.Prefix {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			addr, err := netip.ParseAddr(p)
			if err != nil {
				log.Printf("[CalProxy] WARN: invalid TRUSTED_PROXIES entry %q", p)
				continue
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			out = append(out, netip.PrefixFrom(addr, bits))
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			log.Printf("[CalProxy] WARN: invalid TRUSTED_PROXIES CIDR entry %q", p)
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// ── Sessions ──────────────────────────────────────────────────────────────────

const sessionCookieName = "calproxy_session"
const sessionTTL = 8 * time.Hour

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

func newSessionStore() *sessionStore {
	s := &sessionStore{sessions: make(map[string]time.Time)}
	go s.cleanup()
	return s
}

func (s *sessionStore) create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[id] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	return id, nil
}

func (s *sessionStore) valid(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, id)
		return false
	}
	return true
}

func (s *sessionStore) revoke(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *sessionStore) cleanup() {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, exp := range s.sessions {
			if now.After(exp) {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// ── Persistence ───────────────────────────────────────────────────────────────

type Source struct {
	Token       string    `json:"token"`
	Name        string    `json:"name"`
	UpstreamURL string    `json:"upstreamUrl"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Mode        string    `json:"mode,omitempty"` // "sonarr" | "radarr" | ""
	CreatedAt   time.Time `json:"createdAt"`
}

type SourcePublic struct {
	Token       string    `json:"token"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Mode        string    `json:"mode,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

func (s Source) public() SourcePublic {
	return SourcePublic{
		Token:       s.Token,
		Name:        s.Name,
		Description: s.Description,
		Enabled:     s.Enabled,
		Mode:        s.Mode,
		CreatedAt:   s.CreatedAt,
	}
}

type MergeGroup struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Sources   []string  `json:"sources"` // source tokens
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

// PublicPage defines a public-facing calendar dashboard accessible via a URL slug.
type PublicPage struct {
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Sources     []string `json:"sources"` // source tokens or "merge:<mg-token>"
	IsDefault   bool     `json:"is_default"`
	ShowWebcal  bool     `json:"show_webcal_button"`
	Theme       string   `json:"theme,omitempty"` // "orange"|"gold"|"blue"|"mixed"
}

// persistedData is the on-disk JSON format (v2).
// Legacy format was a plain []Source array and is still read on load.
type persistedData struct {
	Sources     []Source     `json:"sources"`
	MergeGroups []MergeGroup `json:"mergeGroups"`
	PublicPages []PublicPage `json:"publicPages,omitempty"`
}

type store struct {
	mu          sync.RWMutex
	sources     map[string]Source
	mergeGroups map[string]MergeGroup
	publicPages map[string]PublicPage // keyed by slug
	dataFile    string
}

func newStore(dataFile string) *store {
	s := &store{
		sources:     make(map[string]Source),
		mergeGroups: make(map[string]MergeGroup),
		publicPages: make(map[string]PublicPage),
		dataFile:    dataFile,
	}
	s.load()
	return s
}

func (s *store) load() {
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return // missing on first run — not an error
	}

	// Try v2 format (object with "sources" key).
	var pd persistedData
	if err := json.Unmarshal(data, &pd); err == nil && pd.Sources != nil {
		for _, src := range pd.Sources {
			s.sources[src.Token] = src
		}
		for _, mg := range pd.MergeGroups {
			s.mergeGroups[mg.Token] = mg
		}
		// Load public pages, auto-fixing missing slugs from titles.
		for i := range pd.PublicPages {
			if pd.PublicPages[i].Slug == "" {
				pd.PublicPages[i].Slug = slugify(pd.PublicPages[i].Title)
			}
			s.publicPages[pd.PublicPages[i].Slug] = pd.PublicPages[i]
		}
		if err := validatePublicPages(s.listPublicPages()); err != nil {
			log.Printf("[CalProxy] WARN: public_pages config issue: %v", err)
		}
		log.Printf("[CalProxy] INFO: loaded %d source(s), %d merge group(s), %d public page(s)",
			len(s.sources), len(s.mergeGroups), len(s.publicPages))
		return
	}

	// Fall back to v1 format (plain []Source array).
	var list []Source
	if err := json.Unmarshal(data, &list); err != nil {
		log.Printf("[CalProxy] WARN: cannot parse %s, starting fresh: %v", s.dataFile, err)
		return
	}
	for _, src := range list {
		s.sources[src.Token] = src
	}
	log.Printf("[CalProxy] INFO: migrated %d source(s) from legacy format", len(s.sources))
}

// save writes atomically via a temp file → rename to prevent corruption.
func (s *store) save() {
	pd := persistedData{
		Sources:     make([]Source, 0, len(s.sources)),
		MergeGroups: make([]MergeGroup, 0, len(s.mergeGroups)),
		PublicPages: make([]PublicPage, 0, len(s.publicPages)),
	}
	for _, src := range s.sources {
		pd.Sources = append(pd.Sources, src)
	}
	for _, mg := range s.mergeGroups {
		pd.MergeGroups = append(pd.MergeGroups, mg)
	}
	for _, pg := range s.publicPages {
		pd.PublicPages = append(pd.PublicPages, pg)
	}

	data, err := json.MarshalIndent(pd, "", "  ")
	if err != nil {
		log.Printf("[CalProxy] ERROR: marshal data: %v", err)
		return
	}

	dir := filepath.Dir(s.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[CalProxy] ERROR: create data dir %s: %v", dir, err)
		return
	}

	tmp := s.dataFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[CalProxy] ERROR: write temp file: %v", err)
		return
	}
	if err := os.Rename(tmp, s.dataFile); err != nil {
		log.Printf("[CalProxy] ERROR: atomic rename failed: %v", err)
		_ = os.Remove(tmp)
	}
}

func (s *store) listSources() []Source {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Source, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src)
	}
	return out
}

func (s *store) getSource(token string) (Source, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src, ok := s.sources[token]
	return src, ok
}

func (s *store) setSource(src Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources[src.Token] = src
	s.save()
}

func (s *store) deleteSource(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sources[token]; !ok {
		return false
	}
	delete(s.sources, token)
	s.save()
	return true
}

func (s *store) listMergeGroups() []MergeGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]MergeGroup, 0, len(s.mergeGroups))
	for _, mg := range s.mergeGroups {
		out = append(out, mg)
	}
	return out
}

func (s *store) getMergeGroup(token string) (MergeGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mg, ok := s.mergeGroups[token]
	return mg, ok
}

func (s *store) setMergeGroup(mg MergeGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mergeGroups[mg.Token] = mg
	s.save()
}

func (s *store) deleteMergeGroup(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mergeGroups[token]; !ok {
		return false
	}
	delete(s.mergeGroups, token)
	s.save()
	return true
}

func (s *store) listPublicPages() []PublicPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicPage, 0, len(s.publicPages))
	for _, pg := range s.publicPages {
		out = append(out, pg)
	}
	return out
}

func (s *store) getPublicPageBySlug(slug string) (PublicPage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pg, ok := s.publicPages[slug]
	return pg, ok
}

func (s *store) getDefaultPublicPage() (PublicPage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, pg := range s.publicPages {
		if pg.IsDefault {
			return pg, true
		}
	}
	return PublicPage{}, false
}

func (s *store) setPublicPage(pg PublicPage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicPages[pg.Slug] = pg
	s.save()
}

func (s *store) deletePublicPage(slug string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.publicPages[slug]; !ok {
		return false
	}
	delete(s.publicPages, slug)
	s.save()
	return true
}

// slugify converts an arbitrary string into a URL-safe slug.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = slugifyRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "page"
	}
	return s
}

// validatePublicPages checks for duplicate slugs and multiple defaults.
func validatePublicPages(pages []PublicPage) error {
	seen := make(map[string]bool, len(pages))
	defaults := 0
	for _, pg := range pages {
		if !slugRe.MatchString(pg.Slug) {
			return fmt.Errorf("slug %q is not URL-safe (use lowercase letters, digits, hyphens)", pg.Slug)
		}
		if reservedSlugs[pg.Slug] {
			return fmt.Errorf("slug %q conflicts with a built-in route", pg.Slug)
		}
		if seen[pg.Slug] {
			return fmt.Errorf("duplicate slug %q", pg.Slug)
		}
		seen[pg.Slug] = true
		if pg.IsDefault {
			defaults++
		}
	}
	if defaults > 1 {
		return fmt.Errorf("only one public page may be marked is_default, found %d", defaults)
	}
	return nil
}

// ── Startup writability check ─────────────────────────────────────────────────

func checkWritable(dataFile string) {
	dir := filepath.Dir(dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf(
			"[CalProxy] FATAL: cannot create data directory %s: %v\n"+
				"  → Fix: ensure the parent directory is writable, or set PUID/PGID in docker-compose.yml",
			dir, err,
		)
	}
	probe := filepath.Join(dir, ".write_probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf(
			"[CalProxy] FATAL: data directory %s is not writable: %v\n"+
				"  → Fix: chown -R <uid>:<gid> %s  OR set PUID/PGID in docker-compose.yml",
			dir, err, dir,
		)
	}
	f.Close()
	_ = os.Remove(probe)
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

// ── Metadata cache ────────────────────────────────────────────────────────────

// metaCache holds resolved media metadata (episodeId→seriesId, poster URLs).
// Entries are permanent — IDs and poster URLs don't change.
type metaCache struct {
	mu      sync.RWMutex
	entries map[string]string
}

func newMetaCache() *metaCache {
	return &metaCache{entries: make(map[string]string)}
}

func (m *metaCache) get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.entries[key]
	return v, ok
}

func (m *metaCache) set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = value
}

// ── iCal ──────────────────────────────────────────────────────────────────────

var (
	prodidRe     = regexp.MustCompile(`(?m)^PRODID:.*$`)
	veventRe     = regexp.MustCompile(`(?s)BEGIN:VEVENT\r?\n.*?END:VEVENT\r?\n?`)
	slugRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	slugifyRe    = regexp.MustCompile(`[^a-z0-9]+`)
	unfoldRe     = regexp.MustCompile(`\r?\n[ \t]`)
	arrSummaryRe = regexp.MustCompile(`^(.+?)\s+-\s+(\d+)x(\d+)\s+-\s+(.+)$`)
)

type arrParsed struct {
	SeriesName  string
	EpisodeName string
	SE          string
}

func parseArrSummary(summary string) (arrParsed, bool) {
	m := arrSummaryRe.FindStringSubmatch(strings.TrimSpace(summary))
	if m == nil {
		return arrParsed{}, false
	}
	s, _ := strconv.Atoi(m[2])
	e, _ := strconv.Atoi(m[3])
	return arrParsed{
		SeriesName:  strings.TrimSpace(m[1]),
		EpisodeName: strings.TrimSpace(m[4]),
		SE:          fmt.Sprintf("S%02d E%02d", s, e),
	}, true
}

// reservedSlugs are URL segments already claimed by other routes.
var reservedSlugs = map[string]bool{
	"admin": true, "login": true, "logout": true,
	"cal": true, "health": true, "api": true, "img": true,
}

// appVersion and appBranch are injected at build time via -ldflags.
// They fall back to env vars APP_VERSION / APP_BRANCH at runtime.
var (
	appVersion = "dev"
	appBranch  = "dev"
)

func sanitizeICal(body string) string {
	return prodidRe.ReplaceAllString(body, "PRODID:-//CalProxy//CalProxy//EN")
}

func mergeICals(feeds []string, name string) string {
	var sb strings.Builder
	sb.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//CalProxy//CalProxy//EN\r\n")
	sb.WriteString(fmt.Sprintf("X-WR-CALNAME:%s\r\n", name))
	for _, feed := range feeds {
		for _, match := range veventRe.FindAllString(feed, -1) {
			sb.WriteString(match)
			if !strings.HasSuffix(match, "\r\n") {
				sb.WriteString("\r\n")
			}
		}
	}
	sb.WriteString("END:VCALENDAR\r\n")
	return sb.String()
}

// ── Theme helpers ─────────────────────────────────────────────────────────────

var validThemes = map[string]bool{"orange": true, "gold": true, "blue": true, "mixed": true}

// normalizeTheme returns the theme name if valid, or empty string (meaning "use default").
func normalizeTheme(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if validThemes[t] {
		return t
	}
	return ""
}

// normalizeMode returns "sonarr" or "radarr" if valid, otherwise "".
func normalizeMode(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	if m == "sonarr" || m == "radarr" {
		return m
	}
	return ""
}

// ── Upstream fetch ────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 10 * time.Second}

func fetchUpstream(src Source, etag string) (body, newEtag string, notModified bool, err error) {
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

// ── Server ────────────────────────────────────────────────────────────────────

type server struct {
	cfg      config
	db       *store
	cache    *cache
	sessions *sessionStore
	meta     *metaCache
}

func newServer(cfg config) *server {
	return &server{
		cfg:      cfg,
		db:       newStore(cfg.DataFile),
		cache:    newCache(cfg.CacheTTL),
		sessions: newSessionStore(),
		meta:     newMetaCache(),
	}
}

func (s *server) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return s.sessions.valid(cookie.Value)
}

func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthenticated(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints — no auth required.
	mux.HandleFunc("/cal/", s.handleCal)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.HandleFunc("/img/sonarr/series/", s.handleImgSonarr)
	mux.HandleFunc("/img/radarr/poster/", s.handleImgRadarrMeta)

	mux.HandleFunc("/api/public/homepage", s.handlePublicHomepageData)
	mux.HandleFunc("/api/public/page/", s.handlePublicPageData)

	// Admin UI — session auth required.
	mux.HandleFunc("/admin", s.requireAuth(s.handleUI))
	mux.HandleFunc("/", s.handleRoot)

	// Admin API — session auth required.
	mux.HandleFunc("/api/sources", s.requireAuth(s.handleSources))
	mux.HandleFunc("/api/sources/", s.requireAuth(s.handleSourcesToken))
	mux.HandleFunc("/api/merges", s.requireAuth(s.handleMerges))
	mux.HandleFunc("/api/merges/", s.requireAuth(s.handleMergesToken))
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("/api/pages", s.requireAuth(s.handleAdminPublicPages))
	mux.HandleFunc("/api/pages/", s.requireAuth(s.handleAdminPublicPagesSlug))

	return s.withRealIP(mux)
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		// A configured default public page takes priority over the old homepage.
		if pg, ok := s.db.getDefaultPublicPage(); ok {
			http.Redirect(w, r, "/"+pg.Slug, http.StatusFound)
			return
		}
		if s.cfg.PublicHomepage {
			http.ServeFile(w, r, "public/home.html")
			return
		}
		if s.isAuthenticated(r) {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Slug-based public page routing: /{slug}
	slug := strings.TrimPrefix(r.URL.Path, "/")
	if strings.Contains(slug, "/") {
		// Sub-paths under unknown slugs are 404.
		http.NotFound(w, r)
		return
	}
	if _, ok := s.db.getPublicPageBySlug(slug); ok {
		http.ServeFile(w, r, "public/page.html")
		return
	}
	http.NotFound(w, r)
}

func (s *server) withRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = s.realClientAddr(r)
		next.ServeHTTP(w, r)
	})
}

func (s *server) realClientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteAddr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return r.RemoteAddr
	}
	trusted := false
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(remoteAddr) {
			trusted = true
			break
		}
	}
	if !trusted {
		return r.RemoteAddr
	}
	if ip := parseSingleIP(r.Header.Get("X-Real-IP")); ip != "" {
		return net.JoinHostPort(ip, "0")
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, raw := range parts {
			if ip := parseSingleIP(strings.TrimSpace(raw)); ip != "" {
				return net.JoinHostPort(ip, "0")
			}
		}
	}
	return r.RemoteAddr
}

func parseSingleIP(v string) string {
	if v == "" {
		return ""
	}
	if strings.Contains(v, ":") && strings.Count(v, ":") == 1 {
		if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
	}
	addr, err := netip.ParseAddr(strings.Trim(v, "[]"))
	if err != nil {
		return ""
	}
	return addr.String()
}

// ── Auth routes ───────────────────────────────────────────────────────────────

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.isAuthenticated(r) {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "public/login.html")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
			return
		}
		password := r.FormValue("password")
		if err := bcrypt.CompareHashAndPassword(s.cfg.PasswordHash, []byte(password)); err != nil {
			log.Printf("[CalProxy] WARN: failed login attempt from %s", r.RemoteAddr)
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
			return
		}
		sid, err := s.sessions.create()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})
		log.Printf("[CalProxy] INFO: admin logged in from %s", r.RemoteAddr)
		http.Redirect(w, r, "/admin", http.StatusFound)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.revoke(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ── Public routes ─────────────────────────────────────────────────────────────

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

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

	// Merge groups take priority (a merge token must not collide with a source token).
	if mg, ok := s.db.getMergeGroup(token); ok {
		if !mg.Enabled {
			http.NotFound(w, r)
			return
		}
		s.serveMerge(w, mg)
		return
	}

	src, ok := s.db.getSource(token)
	if !ok || !src.Enabled {
		http.NotFound(w, r)
		return
	}

	if entry, fresh := s.cache.fresh(token); fresh {
		serveICal(w, src.Name, s.cfg.CacheTTL, entry.data)
		return
	}

	stale, hasStale := s.cache.get(token)
	var storedEtag string
	if hasStale {
		storedEtag = stale.etag
	}

	body, newEtag, notModified, err := fetchUpstream(src, storedEtag)
	if err != nil {
		log.Printf("[CalProxy] WARN: upstream error for token %s: %v", token, err)
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

func (s *server) serveMerge(w http.ResponseWriter, mg MergeGroup) {
	if entry, fresh := s.cache.fresh(mg.Token); fresh {
		serveICal(w, mg.Name, s.cfg.CacheTTL, entry.data)
		return
	}

	var feeds []string
	for _, srcToken := range mg.Sources {
		src, ok := s.db.getSource(srcToken)
		if !ok || !src.Enabled {
			continue
		}
		if entry, fresh := s.cache.fresh(srcToken); fresh {
			feeds = append(feeds, entry.data)
			continue
		}
		stale, hasStale := s.cache.get(srcToken)
		var etag string
		if hasStale {
			etag = stale.etag
		}
		body, newEtag, notModified, err := fetchUpstream(src, etag)
		if err != nil {
			log.Printf("[CalProxy] WARN: upstream error for source %s in merge %s: %v", srcToken, mg.Token, err)
			if hasStale {
				feeds = append(feeds, stale.data)
			}
			continue
		}
		if notModified {
			s.cache.set(srcToken, cacheEntry{data: stale.data, etag: etag, fetchedAt: time.Now()})
			feeds = append(feeds, stale.data)
		} else {
			sanitized := sanitizeICal(body)
			s.cache.set(srcToken, cacheEntry{data: sanitized, etag: newEtag, fetchedAt: time.Now()})
			feeds = append(feeds, sanitized)
		}
	}

	merged := mergeICals(feeds, mg.Name)
	s.cache.set(mg.Token, cacheEntry{data: merged, fetchedAt: time.Now()})
	serveICal(w, mg.Name, s.cfg.CacheTTL, merged)
}

func serveICal(w http.ResponseWriter, name string, ttl int, body string) {
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", ttl))
	w.Header().Set("X-WR-CALNAME", name)
	_, _ = io.WriteString(w, body)
}

// ── iCal text helpers ─────────────────────────────────────────────────────────

// unfoldBlock removes iCal line-folding (CRLF + whitespace continuation).
func unfoldBlock(block string) string {
	return unfoldRe.ReplaceAllString(block, "")
}

// unescapeICal decodes iCal TEXT escape sequences.
func unescapeICal(s string) string {
	s = strings.ReplaceAll(s, `\\`, "\x00") // protect escaped backslash
	s = strings.ReplaceAll(s, `\,`, ",")
	s = strings.ReplaceAll(s, `\;`, ";")
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, `\N`, "\n")
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, "\x00", `\`)
	return strings.TrimSpace(s)
}

// ── Media source helpers ──────────────────────────────────────────────────────

// findSourceByMode returns the first enabled source with the given mode.
func (s *server) findSourceByMode(mode string) (Source, bool) {
	for _, src := range s.db.listSources() {
		if src.Enabled && src.Mode == mode {
			return src, true
		}
	}
	return Source{}, false
}

// extractAPICredentials derives the API base URL and key from a WebCal upstream URL.
func extractAPICredentials(upstreamURL string) (baseURL, apiKey string) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return "", ""
	}
	return u.Scheme + "://" + u.Host, u.Query().Get("apikey")
}

// resolveImageURL returns a CalProxy image URL for the given VEVENT UID
// based on the source mode.
func (s *server) resolveImageURL(src Source, uid string) string {
	switch src.Mode {
	case "sonarr":
		const prefix = "NzbDrone_episode_"
		if strings.HasPrefix(uid, prefix) {
			episodeID, err := strconv.Atoi(uid[len(prefix):])
			if err != nil {
				return ""
			}
			seriesID, err := s.sonarrSeriesID(src, episodeID)
			if err != nil {
				log.Printf("[CalProxy] WARN: sonarr episode %d lookup: %v", episodeID, err)
				return ""
			}
			return fmt.Sprintf("/img/sonarr/series/%d.jpg", seriesID)
		}
	case "radarr":
		const prefix = "Radarr_movie_"
		if strings.HasPrefix(uid, prefix) {
			rest := uid[len(prefix):]
			if idx := strings.Index(rest, "_"); idx >= 0 {
				rest = rest[:idx]
			}
			metadataID, err := strconv.Atoi(rest)
			if err != nil {
				log.Printf("[CalProxy] WARN: radarr UID %q: cannot parse metadataId from %q", uid, rest)
				return ""
			}
			log.Printf("[CalProxy] DEBUG: radarr UID %q → metadataId %d", uid, metadataID)
			return fmt.Sprintf("/img/radarr/poster/%d.jpg", metadataID)
		}
	}
	return ""
}

// sonarrSeriesID looks up the seriesId for a Sonarr episodeId (cached).
func (s *server) sonarrSeriesID(src Source, episodeID int) (int, error) {
	key := fmt.Sprintf("sonarr_ep_%d", episodeID)
	if v, ok := s.meta.get(key); ok {
		id, _ := strconv.Atoi(v)
		return id, nil
	}
	baseURL, apiKey := extractAPICredentials(src.UpstreamURL)
	if baseURL == "" || apiKey == "" {
		return 0, fmt.Errorf("cannot extract API credentials from source %s", src.Token)
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v3/episode/%d", baseURL, episodeID), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Api-Key", apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("sonarr episode %d returned %d", episodeID, resp.StatusCode)
	}
	var result struct {
		SeriesID int `json:"seriesId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	s.meta.set(key, strconv.Itoa(result.SeriesID))
	return result.SeriesID, nil
}

// sonarrSeriesPosterURL returns the internal poster URL for a Sonarr series (cached).
func (s *server) sonarrSeriesPosterURL(src Source, seriesID int) (string, error) {
	key := fmt.Sprintf("sonarr_series_poster_%d", seriesID)
	if v, ok := s.meta.get(key); ok {
		return v, nil
	}
	baseURL, apiKey := extractAPICredentials(src.UpstreamURL)
	if baseURL == "" || apiKey == "" {
		return "", fmt.Errorf("cannot extract API credentials from source %s", src.Token)
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v3/series/%d", baseURL, seriesID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sonarr series %d returned %d", seriesID, resp.StatusCode)
	}
	var result struct {
		Images []struct {
			CoverType string `json:"coverType"`
			URL       string `json:"url"`
			RemoteURL string `json:"remoteUrl"`
		} `json:"images"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	for _, img := range result.Images {
		if img.CoverType == "poster" {
			posterURL := img.URL
			if posterURL == "" {
				posterURL = img.RemoteURL
			}
			if strings.HasPrefix(posterURL, "/") {
				posterURL = baseURL + posterURL
			}
			s.meta.set(key, posterURL)
			return posterURL, nil
		}
	}
	return "", fmt.Errorf("no poster found for sonarr series %d", seriesID)
}

// radarrImage is the image entry shape returned by Radarr's movie API.
type radarrImage struct {
	CoverType string `json:"coverType"`
	URL       string `json:"url"`
	RemoteURL string `json:"remoteUrl"`
}

// resolveRadarrPosterURL picks the best image URL from a Radarr images slice.
// Finds the poster image from a Radarr images slice and returns the full
// proxy-able URL using only the internal MediaCover path (images[].url).
// The path is taken as-is from the API, query params stripped, then the
// 500px variant is requested (poster.jpg → poster-500.jpg).
// remoteUrl (TMDB/external) is never used — all images must be proxied
// through Radarr's MediaCover by CalProxy.
func resolveRadarrPosterURL(images []radarrImage, baseURL string) string {
	for _, img := range images {
		if img.CoverType != "poster" || img.URL == "" {
			continue
		}
		raw := img.URL
		if strings.HasPrefix(raw, "/") {
			raw = baseURL + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		u.RawQuery = ""
		u.Fragment = ""
		u.Path = strings.Replace(u.Path, "poster.jpg", "poster-500.jpg", 1)
		return u.String()
	}
	return ""
}

// radarrPrefetchPosters bulk-loads all Radarr movie poster URLs via
// GET /api/v3/movie and populates the meta cache in one request.
func (s *server) radarrPrefetchPosters(src Source) error {
	baseURL, apiKey := extractAPICredentials(src.UpstreamURL)
	if baseURL == "" || apiKey == "" {
		return fmt.Errorf("cannot extract API credentials from source %s", src.Token)
	}
	apiURL := fmt.Sprintf("%s/api/v3/movie", baseURL)
	log.Printf("[CalProxy] DEBUG: radarr prefetch fetching %s", apiURL)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("radarr /api/v3/movie returned HTTP %d", resp.StatusCode)
	}
	var movies []struct {
		AlternateTitles []struct {
			MovieMetadataID int `json:"movieMetadataId"`
		} `json:"alternateTitles"`
		Images []radarrImage `json:"images"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&movies); err != nil {
		return err
	}
	log.Printf("[CalProxy] DEBUG: radarr prefetch loaded %d movie(s)", len(movies))
	cached := 0
	for _, movie := range movies {
		if len(movie.AlternateTitles) == 0 {
			continue
		}
		metadataID := movie.AlternateTitles[0].MovieMetadataID
		if metadataID <= 0 {
			continue
		}
		posterURL := resolveRadarrPosterURL(movie.Images, baseURL)
		if posterURL == "" {
			continue
		}
		metaKey := fmt.Sprintf("radarr_meta_poster_%d", metadataID)
		if _, ok := s.meta.get(metaKey); !ok {
			s.meta.set(metaKey, posterURL)
			cached++
		}
	}
	log.Printf("[CalProxy] DEBUG: radarr prefetch cached posters for %d/%d movie(s)", cached, len(movies))
	s.meta.set(fmt.Sprintf("radarr_prefetch_done_%s", src.Token), "1")
	return nil
}

// radarrMoviePosterURLFromMetadataID resolves a poster URL given a movieMetadataId
// extracted from a Radarr calendar UID. metadataId != movie.id; this function
// performs the lookup via /api/v3/movie to find the correct movie.id and its poster.
func (s *server) radarrMoviePosterURLFromMetadataID(src Source, metadataID int) (string, error) {
	key := fmt.Sprintf("radarr_meta_poster_%d", metadataID)
	if v, ok := s.meta.get(key); ok {
		return v, nil
	}

	// On first miss, bulk-load all movies (also populates radarr_meta_poster_* keys).
	prefetchKey := fmt.Sprintf("radarr_prefetch_done_%s", src.Token)
	if _, done := s.meta.get(prefetchKey); !done {
		if err := s.radarrPrefetchPosters(src); err != nil {
			log.Printf("[CalProxy] WARN: radarr bulk prefetch failed: %v", err)
		} else if v, ok := s.meta.get(key); ok {
			return v, nil
		}
	}

	// Fallback: re-scan all movies to find one added after the prefetch.
	baseURL, apiKey := extractAPICredentials(src.UpstreamURL)
	if baseURL == "" || apiKey == "" {
		return "", fmt.Errorf("cannot extract API credentials from source %s", src.Token)
	}
	apiURL := fmt.Sprintf("%s/api/v3/movie", baseURL)
	log.Printf("[CalProxy] DEBUG: radarr metadataId %d fallback scan %s", metadataID, apiURL)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("radarr /api/v3/movie returned HTTP %d", resp.StatusCode)
	}
	var movies []struct {
		AlternateTitles []struct {
			MovieMetadataID int `json:"movieMetadataId"`
		} `json:"alternateTitles"`
		Images []radarrImage `json:"images"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&movies); err != nil {
		return "", err
	}
	for _, movie := range movies {
		matched := false
		for _, at := range movie.AlternateTitles {
			if at.MovieMetadataID == metadataID {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		posterURL := resolveRadarrPosterURL(movie.Images, baseURL)
		if posterURL == "" {
			return "", fmt.Errorf("radarr metadataId %d: no valid poster URL in API response", metadataID)
		}
		s.meta.set(key, posterURL)
		log.Printf("[CalProxy] DEBUG: radarr metadataId %d → poster %s", metadataID, posterURL)
		return posterURL, nil
	}
	return "", fmt.Errorf("radarr metadataId %d not found among %d movies", metadataID, len(movies))
}

// proxyImage fetches an image from an internal URL and streams it as JPEG
// with long-lived cache headers. PNG/GIF are re-encoded to JPEG.
// The apiKey is sent both as X-Api-Key header and as ?apikey= query param
// because Radarr's MediaCover endpoint requires the query param form.
func (s *server) proxyImage(w http.ResponseWriter, imageURL, apiKey string) {
	if apiKey != "" {
		u, err := url.Parse(imageURL)
		if err == nil {
			q := u.Query()
			q.Set("apikey", apiKey)
			u.RawQuery = q.Encode()
			imageURL = u.String()
		}
	}
	req, err := http.NewRequest(http.MethodGet, imageURL, nil)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.NotFound(w, req)
		return
	}
	contentType := resp.Header.Get("Content-Type")
	// Reject HTML — this is a login redirect, not an image.
	if strings.Contains(contentType, "text/html") {
		log.Printf("[CalProxy] WARN: proxyImage: got HTML from %s — likely an auth redirect", imageURL)
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if strings.HasPrefix(contentType, "image/jpeg") {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = io.Copy(w, resp.Body)
		return
	}
	// Buffer non-JPEG for decode + re-encode
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	if err := jpeg.Encode(w, img, &jpeg.Options{Quality: 90}); err != nil {
		log.Printf("[CalProxy] ERROR: JPEG encode: %v", err)
	}
}

// ── Image proxy routes ────────────────────────────────────────────────────────

func (s *server) handleImgSonarr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/img/sonarr/series/")
	rest = strings.TrimSuffix(rest, ".jpg")
	seriesID, err := strconv.Atoi(rest)
	if err != nil || seriesID <= 0 {
		http.NotFound(w, r)
		return
	}
	src, ok := s.findSourceByMode("sonarr")
	if !ok {
		http.Error(w, "No Sonarr source configured", http.StatusServiceUnavailable)
		return
	}
	_, apiKey := extractAPICredentials(src.UpstreamURL)
	posterURL, err := s.sonarrSeriesPosterURL(src, seriesID)
	if err != nil {
		log.Printf("[CalProxy] WARN: sonarr series %d poster: %v", seriesID, err)
		http.NotFound(w, r)
		return
	}
	s.proxyImage(w, posterURL, apiKey)
}

func (s *server) handleImgRadarrMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/img/radarr/poster/")
	rest = strings.TrimSuffix(rest, ".jpg")
	metadataID, err := strconv.Atoi(rest)
	if err != nil || metadataID <= 0 {
		http.NotFound(w, r)
		return
	}
	src, ok := s.findSourceByMode("radarr")
	if !ok {
		http.Error(w, "No Radarr source configured", http.StatusServiceUnavailable)
		return
	}
	_, apiKey := extractAPICredentials(src.UpstreamURL)
	posterURL, err := s.radarrMoviePosterURLFromMetadataID(src, metadataID)
	if err != nil {
		log.Printf("[CalProxy] WARN: radarr metadataId %d poster: %v", metadataID, err)
		http.NotFound(w, r)
		return
	}
	log.Printf("[CalProxy] DEBUG: radarr metadataId %d proxying image %s", metadataID, posterURL)
	s.proxyImage(w, posterURL, apiKey)
}

// ── Admin routes ──────────────────────────────────────────────────────────────

func (s *server) handleSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		all := s.db.listSources()
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
			Mode        string `json:"mode"`
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
			Mode:        normalizeMode(body.Mode),
			CreatedAt:   time.Now().UTC(),
		}
		s.db.setSource(src)
		log.Printf("[CalProxy] INFO: created source %q (token %s, mode %q)", src.Name, src.Token, src.Mode)
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
		if _, ok := s.db.getSource(token); !ok {
			http.NotFound(w, r)
			return
		}
		s.cache.evict(token)
		log.Printf("[CalProxy] INFO: cache purged for token %s", token)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	token := rest
	switch r.Method {
	case http.MethodGet:
		src, ok := s.db.getSource(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, src)

	case http.MethodPut:
		src, ok := s.db.getSource(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Name        *string `json:"name"`
			UpstreamURL *string `json:"upstreamUrl"`
			Description *string `json:"description"`
			Enabled     *bool   `json:"enabled"`
			Mode        *string `json:"mode"`
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
		if body.Mode != nil {
			src.Mode = normalizeMode(*body.Mode)
		}
		s.db.setSource(src)
		s.cache.evict(token)
		log.Printf("[CalProxy] INFO: updated source %s", token)
		writeJSON(w, http.StatusOK, src)

	case http.MethodDelete:
		if !s.db.deleteSource(token) {
			http.NotFound(w, r)
			return
		}
		s.cache.evict(token)
		log.Printf("[CalProxy] INFO: deleted source %s", token)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleMerges(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.db.listMergeGroups())

	case http.MethodPost:
		var body struct {
			Name    string   `json:"name"`
			Sources []string `json:"sources"`
			Enabled *bool    `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
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
		if body.Sources == nil {
			body.Sources = []string{}
		}
		mg := MergeGroup{
			Token:     token,
			Name:      body.Name,
			Sources:   body.Sources,
			Enabled:   enabled,
			CreatedAt: time.Now().UTC(),
		}
		s.db.setMergeGroup(mg)
		log.Printf("[CalProxy] INFO: created merge group %q (token %s)", mg.Name, mg.Token)
		writeJSON(w, http.StatusCreated, mg)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleMergesToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/api/merges/")
	switch r.Method {
	case http.MethodGet:
		mg, ok := s.db.getMergeGroup(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, mg)

	case http.MethodPut:
		mg, ok := s.db.getMergeGroup(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Name    *string  `json:"name"`
			Sources []string `json:"sources"`
			Enabled *bool    `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Name != nil {
			mg.Name = *body.Name
		}
		if body.Sources != nil {
			mg.Sources = body.Sources
		}
		if body.Enabled != nil {
			mg.Enabled = *body.Enabled
		}
		s.db.setMergeGroup(mg)
		s.cache.evict(token)
		log.Printf("[CalProxy] INFO: updated merge group %s", token)
		writeJSON(w, http.StatusOK, mg)

	case http.MethodDelete:
		if !s.db.deleteMergeGroup(token) {
			http.NotFound(w, r)
			return
		}
		s.cache.evict(token)
		log.Printf("[CalProxy] INFO: deleted merge group %s", token)
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
		"sources":     len(s.db.listSources()),
		"mergeGroups": len(s.db.listMergeGroups()),
		"publicPages": len(s.db.listPublicPages()),
		"cached":      s.cache.count(),
		"cacheTtl":    s.cfg.CacheTTL,
	})
}

func (s *server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "public/index.html")
}

// resolvePageSources expands "merge:<token>" entries in a page's Sources list into
// their constituent source tokens. Plain source tokens are passed through unchanged.
// Duplicates are dropped and original ordering is preserved.
// Unknown or disabled merge groups are skipped gracefully.
func (s *server) resolvePageSources(sources []string) []string {
	seen := make(map[string]bool, len(sources))
	out := make([]string, 0, len(sources))
	for _, entry := range sources {
		if strings.HasPrefix(entry, "merge:") {
			mgToken := strings.TrimPrefix(entry, "merge:")
			mg, ok := s.db.getMergeGroup(mgToken)
			if !ok || !mg.Enabled {
				continue
			}
			for _, srcToken := range mg.Sources {
				if !seen[srcToken] {
					seen[srcToken] = true
					out = append(out, srcToken)
				}
			}
		} else {
			if !seen[entry] {
				seen[entry] = true
				out = append(out, entry)
			}
		}
	}
	return out
}

// handlePublicPageData serves the event feed and metadata for a slug-based public page.
func (s *server) handlePublicPageData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.TrimPrefix(r.URL.Path, "/api/public/page/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	pg, ok := s.db.getPublicPageBySlug(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}

	type sourceMeta struct {
		Token       string `json:"token"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	type event struct {
		Date        string `json:"date"`
		Source      string `json:"source"`
		Title       string `json:"title"`
		Description string `json:"description,omitempty"`
		ImageURL    string `json:"imageUrl,omitempty"`
		Episode     string `json:"episode,omitempty"`
		SE          string `json:"se,omitempty"`
		IsArr       bool   `json:"isArr,omitempty"`
	}

	resolvedTokens := s.resolvePageSources(pg.Sources)

	// Build webcal metas from the original sources list so that merge group entries
	// produce a single subscribe URL pointing to /cal/<mg-token>, not individual sources.
	metas := make([]sourceMeta, 0, len(pg.Sources))
	for _, entry := range pg.Sources {
		if strings.HasPrefix(entry, "merge:") {
			mgToken := strings.TrimPrefix(entry, "merge:")
			mg, ok := s.db.getMergeGroup(mgToken)
			if !ok || !mg.Enabled {
				continue
			}
			metas = append(metas, sourceMeta{Token: mg.Token, Name: mg.Name, Description: mg.Name})
		} else {
			src, ok := s.db.getSource(entry)
			if !ok || !src.Enabled {
				continue
			}
			metas = append(metas, sourceMeta{Token: src.Token, Name: src.Name, Description: src.Description})
		}
	}

	// Parse optional filter query params
	showPast := r.URL.Query().Get("showPast") == "true"
	filterMonth := 0
	if m, merr := strconv.Atoi(r.URL.Query().Get("month")); merr == nil && m >= 1 && m <= 12 {
		filterMonth = m
	}

	events := make([]event, 0, 64)
	cutoff := time.Now().UTC().Add(-2 * time.Hour)

	for _, token := range resolvedTokens {
		src, ok := s.db.getSource(token)
		if !ok || !src.Enabled {
			continue
		}
		entry, fresh := s.cache.fresh(src.Token)
		if !fresh {
			body, etag, _, err := fetchUpstream(src, "")
			if err == nil {
				entry = cacheEntry{data: sanitizeICal(body), etag: etag, fetchedAt: time.Now()}
				s.cache.set(src.Token, entry)
			}
		}
		for _, block := range veventRe.FindAllString(entry.data, -1) {
			unfolded := unfoldBlock(block)
			dt := extractICalField(unfolded, "DTSTART")
			rawTitle := extractICalField(unfolded, "SUMMARY")
			if dt == "" || rawTitle == "" {
				continue
			}
			tm, err := parseICalDate(dt)
			if err != nil {
				continue
			}
			if !showPast && tm.Before(cutoff) {
				continue
			}
			if filterMonth != 0 && int(tm.Month()) != filterMonth {
				continue
			}
			uid := extractICalField(unfolded, "UID")
			rawDesc := extractICalField(unfolded, "DESCRIPTION")
			ev := event{
				Date:        tm.Format(time.RFC3339),
				Source:      src.Name,
				Title:       unescapeICal(rawTitle),
				Description: unescapeICal(rawDesc),
			}
			if uid != "" && src.Mode != "" {
				ev.ImageURL = s.resolveImageURL(src, uid)
			}
			if src.Mode == "sonarr" || src.Mode == "radarr" {
				ev.IsArr = true
				if parsed, ok := parseArrSummary(ev.Title); ok {
					ev.Title = parsed.SeriesName
					ev.Episode = parsed.EpisodeName
					ev.SE = parsed.SE
				}
			}
			events = append(events, ev)
		}
	}

	slices.SortFunc(events, func(a, b event) int { return strings.Compare(a.Date, b.Date) })
	limit := 30
	if showPast || filterMonth != 0 {
		limit = 200
	}
	if len(events) > limit {
		events = events[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"title":       pg.Title,
		"show_webcal": pg.ShowWebcal,
		"theme":       pg.Theme,
		"sources":     metas,
		"events":      events,
		"generatedAt": time.Now().UTC(),
		"version":     appVersion + " (" + appBranch + ")",
	})
}

// handleAdminPublicPages handles GET (list) and POST (create) for public pages.
func (s *server) handleAdminPublicPages(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.db.listPublicPages())

	case http.MethodPost:
		var body struct {
			Slug       string   `json:"slug"`
			Title      string   `json:"title"`
			Sources    []string `json:"sources"`
			IsDefault  bool     `json:"is_default"`
			ShowWebcal bool     `json:"show_webcal_button"`
			Theme      string   `json:"theme"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Title == "" {
			http.Error(w, "title is required", http.StatusBadRequest)
			return
		}
		if body.Slug == "" {
			body.Slug = slugify(body.Title)
		}
		if !slugRe.MatchString(body.Slug) {
			http.Error(w, "slug must be lowercase alphanumeric with hyphens", http.StatusBadRequest)
			return
		}
		if reservedSlugs[body.Slug] {
			http.Error(w, "slug conflicts with a built-in route", http.StatusBadRequest)
			return
		}
		if _, exists := s.db.getPublicPageBySlug(body.Slug); exists {
			http.Error(w, "slug already in use", http.StatusConflict)
			return
		}
		// Enforce single default.
		if body.IsDefault {
			if _, hasDefault := s.db.getDefaultPublicPage(); hasDefault {
				http.Error(w, "another page is already marked as default", http.StatusConflict)
				return
			}
		}
		if body.Sources == nil {
			body.Sources = []string{}
		}
		pg := PublicPage{
			Slug:       body.Slug,
			Title:      body.Title,
			Sources:    body.Sources,
			IsDefault:  body.IsDefault,
			ShowWebcal: body.ShowWebcal,
			Theme:      normalizeTheme(body.Theme),
		}
		s.db.setPublicPage(pg)
		log.Printf("[CalProxy] INFO: created public page %q (slug %s)", pg.Title, pg.Slug)
		writeJSON(w, http.StatusCreated, pg)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminPublicPagesSlug handles GET/PUT/DELETE for a single public page by slug.
func (s *server) handleAdminPublicPagesSlug(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/api/pages/")

	switch r.Method {
	case http.MethodGet:
		pg, ok := s.db.getPublicPageBySlug(slug)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, pg)

	case http.MethodPut:
		pg, ok := s.db.getPublicPageBySlug(slug)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Title      *string  `json:"title"`
			Sources    []string `json:"sources"`
			IsDefault  *bool    `json:"is_default"`
			ShowWebcal *bool    `json:"show_webcal_button"`
			Theme      *string  `json:"theme"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if body.Title != nil {
			pg.Title = *body.Title
		}
		if body.Sources != nil {
			pg.Sources = body.Sources
		}
		if body.ShowWebcal != nil {
			pg.ShowWebcal = *body.ShowWebcal
		}
		if body.Theme != nil {
			pg.Theme = normalizeTheme(*body.Theme)
		}
		if body.IsDefault != nil {
			if *body.IsDefault && !pg.IsDefault {
				// Ensure no other page is already the default.
				if existing, hasDefault := s.db.getDefaultPublicPage(); hasDefault && existing.Slug != slug {
					http.Error(w, "another page is already marked as default", http.StatusConflict)
					return
				}
			}
			pg.IsDefault = *body.IsDefault
		}
		s.db.setPublicPage(pg)
		log.Printf("[CalProxy] INFO: updated public page %s", slug)
		writeJSON(w, http.StatusOK, pg)

	case http.MethodDelete:
		if !s.db.deletePublicPage(slug) {
			http.NotFound(w, r)
			return
		}
		log.Printf("[CalProxy] INFO: deleted public page %s", slug)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePublicHomepageData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	type event struct {
		Date   string `json:"date"`
		Source string `json:"source"`
		Title  string `json:"title"`
	}
	events := make([]event, 0, 24)
	now := time.Now().UTC().Add(-2 * time.Hour)
	for _, src := range s.db.listSources() {
		if !src.Enabled {
			continue
		}
		entry, fresh := s.cache.fresh(src.Token)
		if !fresh {
			body, etag, _, err := fetchUpstream(src, "")
			if err == nil {
				entry = cacheEntry{data: sanitizeICal(body), etag: etag, fetchedAt: time.Now()}
				s.cache.set(src.Token, entry)
			}
		}
		for _, block := range veventRe.FindAllString(entry.data, -1) {
			unfolded := unfoldBlock(block)
			dt := extractICalField(unfolded, "DTSTART")
			rawTitle := extractICalField(unfolded, "SUMMARY")
			if dt == "" || rawTitle == "" {
				continue
			}
			tm, err := parseICalDate(dt)
			if err != nil || tm.Before(now) {
				continue
			}
			events = append(events, event{Date: tm.Format(time.RFC3339), Source: src.Name, Title: unescapeICal(rawTitle)})
		}
	}
	slices.SortFunc(events, func(a, b event) int { return strings.Compare(a.Date, b.Date) })
	if len(events) > 30 {
		events = events[:30]
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "generatedAt": time.Now().UTC()})
}

func extractICalField(block, field string) string {
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(line, field+":") {
			return strings.TrimPrefix(line, field+":")
		}
		if strings.HasPrefix(line, field+";") {
			if idx := strings.Index(line, ":"); idx > -1 {
				return line[idx+1:]
			}
		}
	}
	return ""
}

func parseICalDate(v string) (time.Time, error) {
	formats := []string{"20060102T150405Z", "20060102T150405", "20060102"}
	for _, f := range formats {
		if tm, err := time.Parse(f, v); err == nil {
			return tm.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid iCal date")
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(0)
	cfg := loadConfig()

	checkWritable(cfg.DataFile)

	srv := newServer(cfg)
	hs := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      srv.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Println("[CalProxy] INFO: shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.Shutdown(ctx); err != nil {
			log.Printf("[CalProxy] ERROR: shutdown: %v", err)
		}
	}()

	log.Printf("[CalProxy] INFO: listening on :%s  (TTL=%ds  data=%s)", cfg.Port, cfg.CacheTTL, cfg.DataFile)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[CalProxy] FATAL: %v", err)
	}
	log.Println("[CalProxy] INFO: stopped")
}
