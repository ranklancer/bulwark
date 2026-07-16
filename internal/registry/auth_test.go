package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMapAuth_Lookup(t *testing.T) {
	m := MapAuth{
		"registry.example.com": {Username: "u", Password: "p"},
	}
	if _, ok := m.Lookup("registry.example.com"); !ok {
		t.Error("expected hit for registry.example.com")
	}
	if _, ok := m.Lookup("other.example.com"); ok {
		t.Error("unexpected hit for other.example.com")
	}
	if _, ok := MapAuth(nil).Lookup("anything"); ok {
		t.Error("nil MapAuth should be empty")
	}
}

func TestComposite_FirstHitWins(t *testing.T) {
	yaml := MapAuth{"r.example.com": {Username: "yaml-user"}}
	docker := MapAuth{"r.example.com": {Username: "docker-user"}}

	c := CompositeAuth{Auths: []Authenticator{yaml, docker}}
	got, ok := c.Lookup("r.example.com")
	if !ok || got.Username != "yaml-user" {
		t.Errorf("composite.Lookup = %+v ok=%v", got, ok)
	}

	// Nil entries are skipped.
	c2 := CompositeAuth{Auths: []Authenticator{nil, docker}}
	got2, ok := c2.Lookup("r.example.com")
	if !ok || got2.Username != "docker-user" {
		t.Errorf("nil-skip composite.Lookup = %+v ok=%v", got2, ok)
	}
}

func TestDockerConfigAuth_DecodesBase64Auth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	cfg := `{
		"auths": {
			"registry.example.com": {"auth": "` + encoded + `"}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &DockerConfigAuth{Path: path}
	got, ok := d.Lookup("registry.example.com")
	if !ok {
		t.Fatal("expected ok")
	}
	if got.Username != "alice" || got.Password != "secret" {
		t.Errorf("got %+v", got)
	}
}

func TestDockerConfigAuth_PrefersIdentityToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := `{
		"auths": {
			"ghcr.io": {
				"auth": "` + base64.StdEncoding.EncodeToString([]byte("user:pass")) + `",
				"identitytoken": "ghp_long_token"
			}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &DockerConfigAuth{Path: path}
	got, ok := d.Lookup("ghcr.io")
	if !ok {
		t.Fatal("expected ok")
	}
	if got.IdentityToken != "ghp_long_token" {
		t.Errorf("identitytoken not preferred: %+v", got)
	}
	if got.Username != "" || got.Password != "" {
		t.Errorf("identitytoken should clear basic creds: %+v", got)
	}
}

func TestDockerConfigAuth_CredHelperOverridesAuths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := `{
		"auths": {
			"registry.example.com": {"auth": "` + base64.StdEncoding.EncodeToString([]byte("alice:secret")) + `"}
		},
		"credHelpers": {
			"registry.example.com": "secretservice"
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Helper returns different creds than the auths block.
	d := &DockerConfigAuth{
		Path: path,
		ResolveHelper: func(helper, host string) (Credentials, error) {
			if helper != "secretservice" || host != "registry.example.com" {
				t.Errorf("unexpected helper %s host %s", helper, host)
			}
			return Credentials{Username: "from-helper", Password: "secret-from-helper"}, nil
		},
	}
	got, ok := d.Lookup("registry.example.com")
	if !ok {
		t.Fatal("expected ok")
	}
	if got.Username != "from-helper" {
		t.Errorf("helper should win over auths block: %+v", got)
	}
}

func TestDockerConfigAuth_FallsBackToCredsStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := `{"credsStore": "secretservice"}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	d := &DockerConfigAuth{
		Path: path,
		ResolveHelper: func(helper, host string) (Credentials, error) {
			called = true
			return Credentials{Username: "u", Password: "p"}, nil
		},
	}
	if _, ok := d.Lookup("registry.example.com"); !ok {
		t.Fatal("credsStore fallback should fire")
	}
	if !called {
		t.Error("ResolveHelper not invoked")
	}
}

func TestDockerConfigAuth_HelperErrorFallsThrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := `{
		"auths": {"r.example.com": {"auth": "` + base64.StdEncoding.EncodeToString([]byte("backup:backup")) + `"}},
		"credHelpers": {"r.example.com": "broken"}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &DockerConfigAuth{
		Path: path,
		ResolveHelper: func(helper, host string) (Credentials, error) {
			return Credentials{}, errors.New("boom")
		},
	}
	got, ok := d.Lookup("r.example.com")
	if !ok {
		t.Fatal("auths fallback should kick in when helper errors")
	}
	if got.Username != "backup" {
		t.Errorf("got %+v, want fallback creds", got)
	}
}

func TestDockerConfigAuth_MissingFile(t *testing.T) {
	d := &DockerConfigAuth{Path: "/nonexistent/config.json"}
	if _, ok := d.Lookup("any.example.com"); ok {
		t.Error("missing file should yield ok=false")
	}
}

func TestDockerConfigAuth_NilSafe(t *testing.T) {
	var d *DockerConfigAuth
	if _, ok := d.Lookup("any.example.com"); ok {
		t.Error("nil receiver should yield ok=false")
	}
}

// Integration-style test: a private registry that requires Basic auth
// must receive the credentials we configured via the Authenticator,
// retried after the initial 401.
func TestClient_BasicChallengeUsesAuthenticator(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Verify Basic header.
		const want = "Basic " + "YWxpY2U6c2VjcmV0" // base64("alice:secret")
		if r.Header.Get("Authorization") != want {
			t.Errorf("unexpected auth header: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Docker-Content-Digest", "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New()
	client.BaseURL = srv.URL
	client.Auth = MapAuth{
		"registry.example.com": {Username: "alice", Password: "secret"},
	}

	digest, err := client.Resolve(context.Background(), Reference{
		Registry:   "registry.example.com",
		Repository: "myapp",
		Tag:        "1.0",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if digest != "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Errorf("digest = %q", digest)
	}
	if calls != 2 {
		t.Errorf("expected one 401 + one 200; got %d total calls", calls)
	}
}

func TestClient_BasicChallengeWithoutCredsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := New()
	client.BaseURL = srv.URL
	// No Auth configured.

	_, err := client.Resolve(context.Background(), Reference{
		Registry:   "private.example.com",
		Repository: "myapp",
		Tag:        "1.0",
	})
	if err == nil {
		t.Fatal("expected error when Basic challenge has no creds")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("error message %q should mention missing credentials", err.Error())
	}
}

// When the bearer-token endpoint requires Basic auth (Docker Hub PATs,
// GHCR private images), the configured credentials must travel on the
// /token request — not just the manifest retry.
func TestClient_BearerTokenRequestSendsBasicCreds(t *testing.T) {
	tokenSeenAuth := ""
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenSeenAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "issued-token"})
	}))
	defer tokenSrv.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="`+tokenSrv.URL+`",service="example",scope="repository:myapp:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New()
	client.BaseURL = srv.URL
	client.Auth = MapAuth{
		"private-bearer.example.com": {Username: "alice", Password: "secret"},
	}

	if _, err := client.Resolve(context.Background(), Reference{
		Registry:   "private-bearer.example.com",
		Repository: "myapp",
		Tag:        "1.0",
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(tokenSeenAuth, "Basic ") {
		t.Errorf("token endpoint did not receive Basic auth: %q", tokenSeenAuth)
	}
}
