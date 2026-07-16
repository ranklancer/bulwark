package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echoOK is a do-nothing handler that 200s. csrfMiddleware tests assert
// the request either reached it (kept) or didn't (rejected).
func echoOK(reached *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if reached != nil {
			*reached = true
		}
		w.WriteHeader(http.StatusOK)
	}
}

func TestCSRF_GETPasses(t *testing.T) {
	var reached bool
	h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/queue", nil)
	w := httptest.NewRecorder()
	h(w, r)
	if !reached {
		t.Fatal("GET should pass through CSRF unchanged")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestCSRF_PostNoOriginAllowedByDefault(t *testing.T) {
	// curl/scripts that don't send Origin: TrustNoOrigin defaults true.
	var reached bool
	h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h(w, r)
	if !reached {
		t.Fatal("Origin-less POST should pass when TrustNoOrigin=true")
	}
}

func TestCSRF_PostNoOriginRejectedWhenStrict(t *testing.T) {
	cfg := CSRFConfig{TrustNoOrigin: false}
	var reached bool
	h := csrfMiddlewareFunc(cfg, nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h(w, r)
	if reached {
		t.Error("Origin-less POST should be blocked when TrustNoOrigin=false")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestCSRF_PostSecFetchSiteSameOriginPasses(t *testing.T) {
	var reached bool
	h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Origin", "https://evil.example.com") // ignored — Sec-Fetch-Site wins
	w := httptest.NewRecorder()
	h(w, r)
	if !reached {
		t.Errorf("same-origin Sec-Fetch-Site should pass; status=%d", w.Code)
	}
}

func TestCSRF_PostSecFetchSiteCrossSiteRejected(t *testing.T) {
	var reached bool
	h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://attacker.example.com")
	w := httptest.NewRecorder()
	h(w, r)
	if reached {
		t.Error("cross-site POST must be blocked")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestCSRF_PostSameSiteIsRejected(t *testing.T) {
	// "same-site" includes subdomains of the same registrable domain — not
	// good enough for CSRF protection on a single-tenant tool. Reject.
	var reached bool
	h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	r.Header.Set("Sec-Fetch-Site", "same-site")
	w := httptest.NewRecorder()
	h(w, r)
	if reached {
		t.Error("same-site POST must be blocked (subdomains aren't trustworthy)")
	}
}

func TestCSRF_OriginAllowList(t *testing.T) {
	cfg := CSRFConfig{
		AllowedOrigins: []string{"https://other.example.com"},
		TrustNoOrigin:  true,
	}
	var reached bool
	h := csrfMiddlewareFunc(cfg, nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://other.example.com")
	w := httptest.NewRecorder()
	h(w, r)
	if !reached {
		t.Errorf("explicit allow-list origin should pass; status=%d", w.Code)
	}

	// And rejected when the origin isn't on the list and Sec-Fetch-Site is absent.
	reached = false
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	r2.Header.Set("Origin", "https://attacker.example.com")
	w2 := httptest.NewRecorder()
	h(w2, r2)
	if reached {
		t.Error("non-allow-listed origin should be rejected")
	}
	if w2.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w2.Code)
	}
}

func TestCSRF_SameHostOriginPasses(t *testing.T) {
	// Browser sends Origin even on same-origin POSTs. Verify the same-host
	// short-circuit works without an explicit allow-list entry.
	var reached bool
	h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/queue", strings.NewReader("{}"))
	r.Host = "bulwark.example.com"
	r.Header.Set("Origin", "https://bulwark.example.com")
	w := httptest.NewRecorder()
	h(w, r)
	if !reached {
		t.Errorf("same-host Origin should pass; status=%d", w.Code)
	}
}

func TestCSRF_DELETEandPATCHAlsoProtected(t *testing.T) {
	// Mutating-method gate covers DELETE / PUT / PATCH, not just POST.
	for _, m := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
		t.Run(m, func(t *testing.T) {
			var reached bool
			h := csrfMiddlewareFunc(DefaultCSRFConfig(), nil, echoOK(&reached))
			r := httptest.NewRequest(m, "/api/v1/queue/x", nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Origin", "https://attacker.example.com")
			w := httptest.NewRecorder()
			h(w, r)
			if reached {
				t.Errorf("%s cross-site request should be blocked", m)
			}
		})
	}
}
