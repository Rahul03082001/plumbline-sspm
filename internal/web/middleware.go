package web

import (
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// htmxCDN is the only third-party origin the page may load scripts from.
const htmxCDN = "https://cdn.jsdelivr.net"

// csp allows scripts and styles only from our own origin plus the pinned
// htmx file. No inline scripts or styles at all, which is why app.js is a
// separate file and the templates use classes instead of style="...".
var csp = strings.Join([]string{
	"default-src 'self'",
	"script-src 'self' " + htmxCDN,
	"style-src 'self'",
	"img-src 'self' data:",
	"connect-src 'self'",
	"object-src 'none'",
	"base-uri 'none'",
	"form-action 'self'",
	"frame-ancestors 'none'",
}, "; ")

// securityHeaders adds the headers from the spec to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder remembers the status code a handler wrote, for logging.
// It embeds http.ResponseWriter, so every other method passes straight through.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests logs method, route PATTERN (e.g. "GET /f/{id}", not the real
// path), status and duration. Never the query string or headers: those can
// carry tokens or personal data.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		pattern := r.Pattern // set by ServeMux (Go 1.23+) once a route matched
		if pattern == "" {
			pattern = "unmatched"
		}
		log.Info("http request", "method", r.Method, "route", pattern,
			"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

// recoverPanics turns a handler panic into a 500 instead of a dropped connection.
func recoverPanics(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler { // the documented "abort quietly" panic
					panic(p)
				}
				log.Error("handler panic", "panic", p, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ipLimiter gives each client IP its own token bucket: 5 scans per minute.
type ipLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	every    time.Duration
	burst    int
	hops     int
	now      func() time.Time
	lastSwep time.Time
}

type bucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter(perMinute, trustedHops int) *ipLimiter {
	return &ipLimiter{
		buckets: map[string]*bucket{}, every: time.Minute / time.Duration(perMinute),
		burst: perMinute, hops: trustedHops, now: time.Now,
	}
}

// allow reports whether this request's client may create a scan now.
func (l *ipLimiter) allow(r *http.Request) bool {
	ip := clientIP(r, l.hops)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	// Forget idle clients now and then, so the map can't grow forever.
	if now.Sub(l.lastSwep) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastSwep = now
	}
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(rate.Every(l.every), l.burst)}
		l.buckets[ip] = b
	}
	b.lastSeen = now
	return b.lim.AllowN(now, 1)
}

// clientIP returns the address to rate-limit on.
//
// hops = 0: use the TCP peer address (local runs; nothing in front of us).
// hops = N: take the N-th entry from the RIGHT of X-Forwarded-For. Proxies
// APPEND the address they saw, so the right side was written by our own
// infrastructure; the left side is whatever the client typed and can be
// faked. See DECISIONS.md (D3).
func clientIP(r *http.Request, hops int) string {
	if hops > 0 {
		var parts []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			for _, p := range strings.Split(h, ",") {
				if p = strings.TrimSpace(p); p != "" {
					parts = append(parts, p)
				}
			}
		}
		if len(parts) >= hops {
			return parts[len(parts)-hops]
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
