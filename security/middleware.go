package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

/* -------------------------------------------------------------------------- */
/*                        SECURITY MIDDLEWARE                                   */
/* -------------------------------------------------------------------------- */

// ---- API Key Authentication ----

func RequireAPIKey(next http.HandlerFunc, cfg *core.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			slog.Warn("missing API key", "ip", ClientIP(r), "path", r.URL.Path)
			http.Error(w, `{"error":"unauthorized","message":"X-API-Key header required"}`, http.StatusUnauthorized)
			return
		}
		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(key), []byte(cfg.APIKey)) != 1 {
			slog.Warn("invalid API key", "ip", ClientIP(r), "path", r.URL.Path)
			http.Error(w, `{"error":"forbidden","message":"invalid API key"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ---- Rate Limiter v2 with cleanup + blacklist ----

type RateLimiterV2 struct {
	mu        sync.Mutex
	buckets   map[string]*bucketV2
	blacklist map[string]int64 // IP -> block until (unix)
}

type bucketV2 struct {
	tokens    int
	last      time.Time
	rejects   int  // consecutive rejects
	maxTokens int
}

func NewRateLimiterV2() *RateLimiterV2 {
	rl := &RateLimiterV2{
		buckets:   make(map[string]*bucketV2),
		blacklist: make(map[string]int64),
	}
	// Cleanup goroutine — remove stale buckets every 60s
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (r *RateLimiterV2) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	// Remove stale buckets (no activity for 5 minutes)
	for k, b := range r.buckets {
		if now.Sub(b.last) > 5*time.Minute {
			delete(r.buckets, k)
		}
	}
	// Remove expired blacklist entries
	nowUnix := now.Unix()
	for k, until := range r.blacklist {
		if nowUnix > until {
			delete(r.blacklist, k)
		}
	}
}

func (r *RateLimiterV2) Allow(key string, limit int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check blacklist first
	if until, blocked := r.blacklist[key]; blocked {
		if time.Now().Unix() < until {
			return false
		}
		delete(r.blacklist, key) // expired, remove
	}

	now := time.Now()
	b := r.buckets[key]
	if b == nil {
		b = &bucketV2{tokens: limit, last: now, maxTokens: limit}
		r.buckets[key] = b
	}

	// Refill tokens based on time elapsed
	elapsed := now.Sub(b.last)
	if elapsed > 10*time.Second {
		b.tokens = b.maxTokens
		b.last = now
		b.rejects = 0 // reset reject counter on refill
	}

	if b.tokens <= 0 {
		b.rejects++
		// Auto-blacklist after 100 consecutive rejects (brute force protection)
		if b.rejects >= 100 {
			r.blacklist[key] = time.Now().Add(5 * time.Minute).Unix()
			slog.Warn("IP blacklisted for 5 minutes", "ip", key, "rejects", b.rejects)
		}
		return false
	}

	b.tokens--
	return true
}

// ---- Request ID middleware ----

var requestCounter atomic.Uint64

func GenerateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = GenerateRequestID()
		}
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r)
	})
}

// ---- Security Headers ----

func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// HSTS only if running behind TLS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- CORS with configurable origins ----

func WithCORSv2(allowedOrigins string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if allowedOrigins == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" {
				allowed := false
				for _, ao := range strings.Split(allowedOrigins, ",") {
					if strings.TrimSpace(ao) == origin {
						allowed = true
						break
					}
				}
				if allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				}
			}

			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Request-ID, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "3600")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ---- IP Whitelist (optional) ----

func WithIPWhitelist(allowedIPs string) func(http.Handler) http.Handler {
	if allowedIPs == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	allowed := map[string]bool{}
	for _, ip := range strings.Split(allowedIPs, ",") {
		allowed[strings.TrimSpace(ip)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)
			if !allowed[ip] {
				slog.Warn("IP not in whitelist", "ip", ip, "path", r.URL.Path)
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---- Body limiter ----

func WithBodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// ---- Method enforcement ----

func RequireGET(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func RequirePOST(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// ---- Client IP extraction ----

func ClientIP(r *http.Request) string {
	// Check X-Forwarded-For (first entry is original client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}
	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ---- Secure HTTP Server builder ----

func NewSecureServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}
}

// ---- Health check endpoint ----

// MempoolSizer is an interface for getting mempool size without import cycle.
type MempoolSizer interface {
	MempoolSize() int
}

func HealthHandler(chain *core.Chain, mu *sync.RWMutex, sizer MempoolSizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		height := 0
		blocks := 0
		accounts := 0
		if chain != nil {
			blocks = len(chain.Blocks)
			if blocks > 0 {
				height = chain.Blocks[blocks-1].Header.Height
			}
			accounts = len(chain.State)
		}
		mempoolSize := sizer.MempoolSize()
		mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","height":%d,"blocks":%d,"accounts":%d,"mempool":%d,"version":"2.0.0"}`,
			height, blocks, accounts, mempoolSize)
	}
}

// ---- Chain middleware composer ----

func ChainMiddleware(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// ---- Rate limit wrapper ----

func WithLimit(next http.HandlerFunc, limit int, rl *RateLimiterV2) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !rl.Allow(ip, limit) {
			http.Error(w, `{"error":"rate_limited"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
