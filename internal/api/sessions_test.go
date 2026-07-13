package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
)

func TestSessionScheme_IssueAndVerify(t *testing.T) {
	s, err := NewSessionScheme(0)
	if err != nil {
		t.Fatal(err)
	}

	value, exp := s.Issue()
	if value == "" {
		t.Fatal("Issue returned empty value")
	}
	if exp.Before(time.Now().Add(11 * time.Hour)) {
		t.Errorf("default TTL should be 12h; got expiry %v", exp)
	}
	if !s.Verify(value) {
		t.Error("freshly issued cookie failed Verify")
	}
}

func TestSessionScheme_VerifyRejectsTampered(t *testing.T) {
	s, _ := NewSessionScheme(time.Minute)
	value, _ := s.Issue()

	// Mutate one byte of the signature.
	idx := strings.IndexByte(value, '.')
	if idx < 0 {
		t.Fatal("malformed value")
	}
	// Flip the first signature byte to a value guaranteed to differ, so the
	// "tamper" is never a no-op (a fixed "X" collides when the byte is already
	// 'X', which made this test intermittently pass a valid cookie).
	repl := byte('X')
	if value[idx+1] == repl {
		repl = 'Y'
	}
	tampered := value[:idx+1] + string(repl) + value[idx+2:]
	if s.Verify(tampered) {
		t.Error("tampered cookie should not verify")
	}
}

func TestSessionScheme_VerifyRejectsExpired(t *testing.T) {
	s, _ := NewSessionScheme(1 * time.Second)
	value, _ := s.Issue()
	// Move the clock forward past expiry.
	s.Now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if s.Verify(value) {
		t.Error("expired cookie should not verify")
	}
}

func TestSessionScheme_VerifyRejectsCrossSigned(t *testing.T) {
	a, _ := NewSessionScheme(time.Minute)
	b, _ := NewSessionScheme(time.Minute)
	value, _ := a.Issue()
	if b.Verify(value) {
		t.Error("cookie signed by a should not verify under b's secret")
	}
}

func TestSessionScheme_VerifyRejectsMalformed(t *testing.T) {
	s, _ := NewSessionScheme(time.Minute)
	cases := []string{
		"",
		"no-dot",
		"123.",
		".sig-only",
		"notanumber.sig",
	}
	for _, v := range cases {
		if s.Verify(v) {
			t.Errorf("malformed value %q should not verify", v)
		}
	}
}

func TestCookieOrInnerAuth_CookieWins(t *testing.T) {
	s, _ := NewSessionScheme(time.Minute)
	value, _ := s.Issue()

	a := CookieOrInnerAuth{
		Inner:    BearerAuth{Token: "right-bearer"},
		Sessions: s,
	}

	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id.User != "session" {
		t.Errorf("expected User=session, got %+v", id)
	}
}

func TestCookieOrInnerAuth_FallsThroughOnNoCookie(t *testing.T) {
	s, _ := NewSessionScheme(time.Minute)
	a := CookieOrInnerAuth{
		Inner:    BearerAuth{Token: "right-bearer"},
		Sessions: s,
	}

	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.Header.Set("Authorization", "Bearer right-bearer")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id.User != "bearer" {
		t.Errorf("expected fallback to bearer; got %+v", id)
	}
}

func TestCookieOrInnerAuth_InvalidCookieFallsThrough(t *testing.T) {
	s, _ := NewSessionScheme(time.Minute)
	a := CookieOrInnerAuth{
		Inner:    BearerAuth{Token: "right-bearer"},
		Sessions: s,
	}
	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "garbage.notavalidsig"})
	r.Header.Set("Authorization", "Bearer right-bearer")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id.User != "bearer" {
		t.Errorf("invalid cookie should fall through; got %+v", id)
	}
}

// Integration: POST /api/v1/sessions with a valid bearer issues a
// cookie; subsequent requests with the cookie alone (no Authorization
// header) succeed.
func TestStateAPI_SessionLoginAndCookieAuth(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	scheme, _ := NewSessionScheme(time.Hour)

	bearer := BearerAuth{Token: "secret-token"}
	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: bearer,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// First, listing without auth fails.
	res, err := http.Get(srv.URL + "/api/v1/scans")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauth listing = %d, want 401", res.StatusCode)
	}
	res.Body.Close()

	// Login with bearer → 200 + cookie.
	loginReq, _ := http.NewRequestWithContext(context.Background(), "POST",
		srv.URL+"/api/v1/sessions", strings.NewReader(""))
	loginReq.Header.Set("Authorization", "Bearer secret-token")
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", loginRes.StatusCode)
	}
	var cookieVal string
	for _, c := range loginRes.Cookies() {
		if c.Name == SessionCookieName {
			cookieVal = c.Value
			if !c.HttpOnly {
				t.Error("session cookie must be HttpOnly")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Error("session cookie must be SameSite=Lax")
			}
		}
	}
	loginRes.Body.Close()
	if cookieVal == "" {
		t.Fatal("login response missing session cookie")
	}

	// Listing with cookie alone (no Authorization) succeeds.
	listReq, _ := http.NewRequestWithContext(context.Background(), "GET",
		srv.URL+"/api/v1/scans", nil)
	listReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieVal})
	listRes, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	if listRes.StatusCode != http.StatusOK {
		t.Errorf("cookie-auth listing = %d, want 200", listRes.StatusCode)
	}
	listRes.Body.Close()
}

func TestStateAPI_SessionLoginRejectsBadBearer(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	scheme, _ := NewSessionScheme(time.Hour)

	bearer := BearerAuth{Token: "secret-token"}
	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: bearer,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sessions", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad bearer login = %d, want 401", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			t.Error("rejected login should not set a session cookie")
		}
	}
	res.Body.Close()
}

// A cookie that expired must NOT renew itself: the session-login
// endpoint always uses the *inner* authenticator, never the cookie.
func TestStateAPI_SessionEndpointIgnoresCookieForRenewal(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	// Issue a still-valid cookie via a separate scheme — the server's
	// own scheme will reject the foreign cookie. (We re-use the same
	// secret-leak attack model: even with a working cookie, you still
	// need the bearer to mint a new one.)
	scheme, _ := NewSessionScheme(time.Hour)
	value, _ := scheme.Issue()

	bearer := BearerAuth{Token: "secret-token"}
	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: bearer, // cookie SHOULD NOT satisfy this
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sessions", strings.NewReader(""))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("cookie-only renewal = %d, want 401", res.StatusCode)
	}
	res.Body.Close()
}

// Logout clears the cookie regardless of bearer auth.
func TestStateAPI_SessionLogout(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	scheme, _ := NewSessionScheme(time.Hour)

	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: AnonymousAuth{}, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: AnonymousAuth{},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/sessions", nil)
	req.Header.Set("Origin", srv.URL)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("logout = %d, want 204", res.StatusCode)
	}
	cleared := false
	for _, c := range res.Cookies() {
		if c.Name == SessionCookieName && c.MaxAge == -1 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout should set cookie with MaxAge=-1")
	}
	res.Body.Close()
}

// TestStateAPI_GetSessionProbe asserts the SPA's session probe:
//   - 200 + body{authenticated, session_endpoints_enabled} when authed
//   - session_endpoints_enabled=false in anonymous mode
//   - 401 when bearer auth is configured and missing
func TestStateAPI_GetSessionProbe(t *testing.T) {
	t.Run("authed with bearer", func(t *testing.T) {
		st, _ := store.Open(t.TempDir())
		bearer := BearerAuth{Token: "tok"}
		h := &StateHandler{Store: st, Auth: bearer, SessionInnerAuth: bearer}
		mux := http.NewServeMux()
		h.Register(mux)
		srv := httptest.NewServer(mux)
		defer srv.Close()

		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer tok")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", res.StatusCode)
		}
		var body map[string]any
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["authenticated"] != true {
			t.Errorf("body[authenticated] = %v, want true", body["authenticated"])
		}
		if body["session_endpoints_enabled"] != false {
			t.Errorf("body[session_endpoints_enabled] = %v, want false (Sessions nil)",
				body["session_endpoints_enabled"])
		}
	})

	t.Run("authed with sessions enabled", func(t *testing.T) {
		st, _ := store.Open(t.TempDir())
		scheme, _ := NewSessionScheme(time.Hour)
		bearer := BearerAuth{Token: "tok"}
		h := &StateHandler{
			Store:            st,
			Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
			Sessions:         scheme,
			SessionInnerAuth: bearer,
		}
		mux := http.NewServeMux()
		h.Register(mux)
		srv := httptest.NewServer(mux)
		defer srv.Close()

		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer tok")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		if body["session_endpoints_enabled"] != true {
			t.Errorf("body[session_endpoints_enabled] = %v, want true",
				body["session_endpoints_enabled"])
		}
	})

	t.Run("unauthed returns 401", func(t *testing.T) {
		st, _ := store.Open(t.TempDir())
		bearer := BearerAuth{Token: "tok"}
		h := &StateHandler{Store: st, Auth: bearer, SessionInnerAuth: bearer}
		mux := http.NewServeMux()
		h.Register(mux)
		srv := httptest.NewServer(mux)
		defer srv.Close()

		res, err := http.Get(srv.URL + "/api/v1/sessions")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous probe = %d, want 401", res.StatusCode)
		}
	})

	t.Run("anonymous mode returns 200 with disabled session endpoints", func(t *testing.T) {
		st, _ := store.Open(t.TempDir())
		h := &StateHandler{Store: st, Auth: AnonymousAuth{}}
		mux := http.NewServeMux()
		h.Register(mux)
		srv := httptest.NewServer(mux)
		defer srv.Close()

		res, err := http.Get(srv.URL + "/api/v1/sessions")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("anonymous probe = %d, want 200", res.StatusCode)
		}
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		if body["session_endpoints_enabled"] != false {
			t.Errorf("anonymous-mode body[session_endpoints_enabled] = %v, want false",
				body["session_endpoints_enabled"])
		}
	})
}

// TestStateAPI_SessionLoginRespectsForwardedProto asserts the
// X-Forwarded-Proto trust path: behind a TLS-terminating reverse
// proxy the daemon's r.TLS is nil even though the client connection
// is HTTPS. The cookie must still get the Secure flag so it isn't
// returned over a downgraded HTTP request.
func TestStateAPI_SessionLoginRespectsForwardedProto(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	scheme, _ := NewSessionScheme(time.Hour)
	bearer := BearerAuth{Token: "tok"}
	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: bearer,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux) // plain HTTP — r.TLS will be nil
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sessions", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https") // the proxy's signal
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	var found *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == SessionCookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("session cookie missing")
	}
	if !found.Secure {
		t.Errorf("Secure flag not set despite X-Forwarded-Proto: https")
	}
}

func TestStateAPI_SessionLoginNoSecureWithoutForwardedProto(t *testing.T) {
	// Sanity: without X-Forwarded-Proto, plain HTTP login still
	// works but the cookie doesn't carry Secure (correct for
	// localhost / dev deployments).
	st, _ := store.Open(t.TempDir())
	scheme, _ := NewSessionScheme(time.Hour)
	bearer := BearerAuth{Token: "tok"}
	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: bearer,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sessions", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Name == SessionCookieName && c.Secure {
			t.Errorf("Secure flag set on plain-HTTP login without X-Forwarded-Proto")
		}
	}
}

func TestStateAPI_SessionResponseBody(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	scheme, _ := NewSessionScheme(time.Hour)
	bearer := BearerAuth{Token: "tok"}

	h := &StateHandler{
		Store:            st,
		Auth:             CookieOrInnerAuth{Inner: bearer, Sessions: scheme},
		Sessions:         scheme,
		SessionInnerAuth: bearer,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sessions", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["expires_at"] == nil {
		t.Errorf("response body missing expires_at: %+v", body)
	}
	if body["ttl_seconds"] == nil {
		t.Errorf("response body missing ttl_seconds: %+v", body)
	}
}
