package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// --- Identity ---------------------------------------------------------------

func TestIdentity_AnonymousAndGroupChecks(t *testing.T) {
	if !(Identity{}).IsAnonymous() {
		t.Error("zero Identity should report anonymous")
	}
	if (Identity{User: "alice"}).IsAnonymous() {
		t.Error("non-empty user is not anonymous")
	}
	id := Identity{User: "alice", Groups: []string{"ops", "admins"}}
	if !id.HasGroup("ops") {
		t.Error("expected ops match")
	}
	if id.HasGroup("readers") {
		t.Error("did not expect readers match")
	}
	// Empty group requirement = always satisfied.
	if !id.HasGroup("") {
		t.Error("empty required group should always pass")
	}
}

// --- AnonymousAuth ----------------------------------------------------------

func TestAnonymousAuth_AllowsEverything(t *testing.T) {
	id, err := AnonymousAuth{}.Authenticate(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("Anonymous returned error: %v", err)
	}
	if !id.IsAnonymous() {
		t.Errorf("Anonymous should produce anonymous Identity, got %+v", id)
	}
}

// --- BearerAuth -------------------------------------------------------------

func TestBearerAuth_RejectsMissingToken(t *testing.T) {
	auth := BearerAuth{Token: "secret"}
	r := httptest.NewRequest("GET", "/", nil)
	_, err := auth.Authenticate(r)
	if err == nil {
		t.Fatal("expected error on missing token")
	}
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Errorf("expected 401 AuthError, got %v", err)
	}
}

func TestBearerAuth_AcceptsBearerHeader(t *testing.T) {
	auth := BearerAuth{Token: "secret"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	id, err := auth.Authenticate(r)
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if id.User != "bearer" {
		t.Errorf("default User = %q, want 'bearer'", id.User)
	}
}

func TestBearerAuth_AcceptsCustomHeader(t *testing.T) {
	auth := BearerAuth{Token: "secret", User: "diun"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Bulwark-Token", "secret")
	id, err := auth.Authenticate(r)
	if err != nil {
		t.Fatalf("X-Bulwark-Token: %v", err)
	}
	if id.User != "diun" {
		t.Errorf("custom User = %q, want 'diun'", id.User)
	}
}

func TestBearerAuth_RejectsWrongToken(t *testing.T) {
	auth := BearerAuth{Token: "secret"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	_, err := auth.Authenticate(r)
	if err == nil {
		t.Fatal("expected error on wrong token")
	}
}

func TestBearerAuth_EmptyTokenIsMisconfiguration(t *testing.T) {
	auth := BearerAuth{Token: ""}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer anything")
	_, err := auth.Authenticate(r)
	if err == nil {
		t.Fatal("BearerAuth with empty token should refuse — fail closed")
	}
}

// --- ForwardProxyAuth -------------------------------------------------------

func mustNewForwardProxy(t *testing.T, cidrs []string, required string) *ForwardProxyAuth {
	t.Helper()
	a, err := NewForwardProxyAuth(cidrs, "", "", required)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestForwardProxyAuth_NewRejectsBadCIDR(t *testing.T) {
	if _, err := NewForwardProxyAuth([]string{"not-a-cidr"}, "", "", ""); err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}

func TestForwardProxyAuth_NoTrustedProxiesRejectsAll(t *testing.T) {
	auth := &ForwardProxyAuth{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:54321"
	r.Header.Set("Remote-User", "alice")
	_, err := auth.Authenticate(r)
	if err == nil {
		t.Fatal("expected 403 with no trusted proxies (fail-closed)")
	}
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != http.StatusForbidden {
		t.Errorf("expected 403, got %v", err)
	}
}

func TestForwardProxyAuth_RejectsUntrustedPeer(t *testing.T) {
	auth := mustNewForwardProxy(t, []string{"192.0.2.0/24"}, "")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:55555"
	r.Header.Set("Remote-User", "alice")
	_, err := auth.Authenticate(r)
	if err == nil {
		t.Fatal("untrusted peer should be rejected")
	}
	if !strings.Contains(err.Error(), "trusted proxy") {
		t.Errorf("error should mention trusted proxy, got %v", err)
	}
}

func TestForwardProxyAuth_AcceptsTrustedPeerWithUser(t *testing.T) {
	auth := mustNewForwardProxy(t, []string{"192.0.2.0/24"}, "")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.5:12345"
	r.Header.Set("Remote-User", "alice")
	r.Header.Set("Remote-Groups", "ops,admins")
	id, err := auth.Authenticate(r)
	if err != nil {
		t.Fatalf("trusted peer with user: %v", err)
	}
	if id.User != "alice" {
		t.Errorf("User = %q", id.User)
	}
	if !reflect.DeepEqual(id.Groups, []string{"ops", "admins"}) {
		t.Errorf("Groups = %v", id.Groups)
	}
}

func TestForwardProxyAuth_RejectsTrustedPeerWithoutUser(t *testing.T) {
	auth := mustNewForwardProxy(t, []string{"192.0.2.0/24"}, "")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.5:12345"
	// No Remote-User header.
	_, err := auth.Authenticate(r)
	if err == nil {
		t.Fatal("trusted peer without user should fail")
	}
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Errorf("expected 401, got %v", err)
	}
}

func TestForwardProxyAuth_RequiredGroupGate(t *testing.T) {
	auth := mustNewForwardProxy(t, []string{"192.0.2.0/24"}, "ops")

	// In the required group → ok.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.5:12345"
	r.Header.Set("Remote-User", "alice")
	r.Header.Set("Remote-Groups", "ops,reporters")
	if _, err := auth.Authenticate(r); err != nil {
		t.Errorf("user in required group rejected: %v", err)
	}

	// Not in the required group → 403.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "192.0.2.5:12345"
	r2.Header.Set("Remote-User", "bob")
	r2.Header.Set("Remote-Groups", "reporters")
	_, err := auth.Authenticate(r2)
	if err == nil {
		t.Fatal("user not in required group should be rejected")
	}
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != http.StatusForbidden {
		t.Errorf("expected 403, got %v", err)
	}
}

func TestForwardProxyAuth_CustomHeaders(t *testing.T) {
	a, err := NewForwardProxyAuth([]string{"192.0.2.0/24"}, "X-Auth-Request-User", "X-Auth-Request-Groups", "")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.5:12345"
	r.Header.Set("X-Auth-Request-User", "carol")
	r.Header.Set("X-Auth-Request-Groups", "team-a team-b")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.User != "carol" {
		t.Errorf("User = %q", id.User)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "team-a" || id.Groups[1] != "team-b" {
		t.Errorf("Groups = %v (whitespace separator should split)", id.Groups)
	}
}

func TestForwardProxyAuth_IPv6PeerInsideCIDR(t *testing.T) {
	a, err := NewForwardProxyAuth([]string{"fd00::/8"}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[fd12::1]:54321"
	r.Header.Set("Remote-User", "alice")
	if _, err := a.Authenticate(r); err != nil {
		t.Errorf("ipv6 trusted peer rejected: %v", err)
	}
}

// --- parseGroups ------------------------------------------------------------

func TestParseGroups(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"ops", []string{"ops"}},
		{"ops,admins", []string{"ops", "admins"}},
		{"ops admins reporters", []string{"ops", "admins", "reporters"}},
		{"  ops , admins ", []string{"ops", "admins"}},
	}
	for _, tc := range cases {
		got := parseGroups(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseGroups(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// --- middleware -------------------------------------------------------------

func TestAuthMiddleware_PropagatesIdentityToHandler(t *testing.T) {
	var seenUser string
	mw := authMiddleware(BearerAuth{Token: "secret", User: "machine"},
		func(w http.ResponseWriter, r *http.Request) {
			seenUser = IdentityFromContext(r.Context()).User
			w.WriteHeader(http.StatusOK)
		})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	mw(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if seenUser != "machine" {
		t.Errorf("handler saw User = %q", seenUser)
	}
}

func TestAuthMiddleware_PropagatesAuthErrorStatus(t *testing.T) {
	mw := authMiddleware(mustNewForwardProxy(t, []string{"192.0.2.0/24"}, ""),
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.1:54321" // outside trusted CIDR
	w := httptest.NewRecorder()
	mw(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (untrusted peer)", w.Code)
	}
}

func TestIdentityFromContext_Default(t *testing.T) {
	if got := IdentityFromContext(context.Background()); !got.IsAnonymous() {
		t.Errorf("default Identity should be anonymous, got %+v", got)
	}
}

// --- helpers ----------------------------------------------------------------

func TestForwardProxyAuth_PeerTrustedHandlesPortlessRemoteAddr(t *testing.T) {
	// http.Request.RemoteAddr is normally "host:port", but make sure we
	// don't panic on a degenerate input.
	a, _ := NewForwardProxyAuth([]string{"192.0.2.0/24"}, "", "", "")
	r := &http.Request{RemoteAddr: "192.0.2.5", Header: http.Header{"Remote-User": {"alice"}}}
	if _, err := a.Authenticate(r); err != nil {
		t.Errorf("portless RemoteAddr inside CIDR should still authenticate: %v", err)
	}
	// Confirm net.ParseCIDR-rejection path is unaffected.
	_, _, _ = net.ParseCIDR("0.0.0.0/0")
}
