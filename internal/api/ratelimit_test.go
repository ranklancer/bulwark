package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowsBurstThenRejects(t *testing.T) {
	rl := &RateLimiter{Capacity: 3, RefillEvery: time.Hour, Now: func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}}
	for i := 0; i < 3; i++ {
		if !rl.Allow("client-1") {
			t.Errorf("burst[%d] should be allowed", i)
		}
	}
	if rl.Allow("client-1") {
		t.Error("4th request should be rejected after exhausting burst")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	rl := &RateLimiter{Capacity: 1, RefillEvery: time.Second, Now: func() time.Time { return now }}

	if !rl.Allow("c") {
		t.Fatal("first should pass")
	}
	if rl.Allow("c") {
		t.Fatal("second within zero-elapsed should fail")
	}
	now = t0.Add(2 * time.Second) // 2 tokens accrued, capped at Capacity=1
	if !rl.Allow("c") {
		t.Errorf("after refill, request should pass")
	}
	if rl.Allow("c") {
		t.Errorf("should not pass twice — capacity=1")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	rl := &RateLimiter{Capacity: 1, RefillEvery: time.Hour, Now: func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}}
	if !rl.Allow("a") {
		t.Fatal("a's first request should pass")
	}
	if !rl.Allow("b") {
		t.Fatal("b's first request should pass — different bucket")
	}
	if rl.Allow("a") {
		t.Error("a's second request should fail (per-key tracking)")
	}
}

func TestRateLimiter_NilOrZeroCapacityAllowsAll(t *testing.T) {
	var nilLimiter *RateLimiter
	if !nilLimiter.Allow("anything") {
		t.Error("nil limiter should allow")
	}
	zero := &RateLimiter{}
	if !zero.Allow("anything") {
		t.Error("zero-capacity limiter should allow")
	}
}

func TestRateLimiter_GarbageCollectsStaleBuckets(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	rl := &RateLimiter{Capacity: 1, RefillEvery: time.Second, Now: func() time.Time { return now }}
	rl.Allow("ephemeral")
	rl.Allow("persistent")

	rl.mu.Lock()
	if _, ok := rl.buckets["ephemeral"]; !ok {
		rl.mu.Unlock()
		t.Fatal("ephemeral bucket missing right after creation")
	}
	rl.mu.Unlock()

	now = t0.Add(20 * time.Second) // 20× RefillEvery — past the GC cutoff
	rl.Allow("persistent")          // touches persistent's bucket; triggers GC pass

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.buckets["ephemeral"]; ok {
		t.Errorf("expected ephemeral bucket to be GC'd")
	}
	if _, ok := rl.buckets["persistent"]; !ok {
		t.Errorf("persistent bucket should still be present")
	}
}

func TestRateLimiter_Middleware_429WithRetryAfter(t *testing.T) {
	rl := &RateLimiter{Capacity: 1, RefillEvery: time.Hour}
	called := 0
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "192.0.2.1:1234"
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: %d, want 200", w1.Code)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "192.0.2.1:5678"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: %d, want 429", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("429 response should include Retry-After")
	}
	if called != 1 {
		t.Errorf("inner handler called %d times, want 1", called)
	}
}

func TestClientIP_HandlesPortlessAddress(t *testing.T) {
	r := &http.Request{RemoteAddr: "192.0.2.1"}
	if got := clientIP(r); got != "192.0.2.1" {
		t.Errorf("clientIP = %q", got)
	}
}
