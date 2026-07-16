package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a per-IP token-bucket limiter intended for the small
// HTTP surface Bulwark exposes. The implementation is deliberately
// dependency-free — `golang.org/x/time/rate` would be cleaner but adds a
// transitive dep that isn't justified for our throughput.
//
// Buckets are evicted lazily: any client that hasn't been seen in
// 10× the bucket-fill period is GC'd on the next sweep, so a busy public
// listener doesn't accumulate one bucket per random scanner forever.
type RateLimiter struct {
	// Capacity is the maximum number of tokens a bucket can hold.
	// Burst size = Capacity. Default 10.
	Capacity int

	// RefillEvery is the wall-clock interval at which one token is added.
	// Effective long-run rate = 1/RefillEvery requests. Default 1 second.
	RefillEvery time.Duration

	// Now is overrideable for deterministic tests; defaults to time.Now.
	Now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// DefaultRateLimiter returns a sensibly-tuned limiter: 60 requests per
// minute steady-state with a 10-token burst. Plenty of headroom for the
// dashboard's 30-second auto-refresh + occasional human clicks; keeps
// runaway scripts and DoS bursts in check.
func DefaultRateLimiter() *RateLimiter {
	return &RateLimiter{Capacity: 10, RefillEvery: time.Second}
}

// Allow reports whether the request from key (typically an IP) may proceed.
// On allow, one token is consumed; on deny, no token is consumed.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil || r.Capacity <= 0 {
		// nil / zero-capacity = unconfigured = allow everything.
		return true
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buckets == nil {
		r.buckets = map[string]*bucket{}
	}
	r.gcLocked(now)

	b, ok := r.buckets[key]
	if !ok {
		// Fresh client: starts at full capacity minus the request we're
		// about to allow.
		r.buckets[key] = &bucket{tokens: float64(r.Capacity) - 1, last: now}
		return true
	}
	// Refill: how many tokens have ticked in since we last saw this client?
	elapsed := now.Sub(b.last)
	if elapsed > 0 && r.RefillEvery > 0 {
		add := float64(elapsed) / float64(r.RefillEvery)
		b.tokens += add
		if b.tokens > float64(r.Capacity) {
			b.tokens = float64(r.Capacity)
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Middleware wraps next with per-IP rate limiting. The IP is derived from
// the request's RemoteAddr; X-Forwarded-For is intentionally ignored at
// this layer because we can't tell trusted proxies from spoofers without
// the same configuration ForwardProxyAuth carries. Upstream proxies
// preserving the client IP via PROXY-protocol or by setting RemoteAddr
// before the request reaches us are honoured naturally.
func (r *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		key := clientIP(req)
		if !r.Allow(key) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// MiddlewareFunc is the HandlerFunc-shaped sister of Middleware.
func (r *RateLimiter) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	wrapped := r.Middleware(next)
	return wrapped.ServeHTTP
}

func (r *RateLimiter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// gcLocked drops bucket records whose owner hasn't been seen in
// 10× RefillEvery. Bounded sweep — runs at most once per RefillEvery to
// keep Allow() fast under sustained load.
func (r *RateLimiter) gcLocked(now time.Time) {
	if r.RefillEvery <= 0 {
		return
	}
	if now.Sub(r.lastGC) < r.RefillEvery {
		return
	}
	r.lastGC = now
	cutoff := now.Add(-10 * r.RefillEvery)
	for k, b := range r.buckets {
		if b.last.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}

// clientIP extracts the client IP from r.RemoteAddr, falling back to
// the raw value for inputs that don't have a port (rare).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
