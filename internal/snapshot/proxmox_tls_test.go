package snapshot

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tlsFakeServer returns an HTTPS test server that answers 200 on every path
// (so Available's GET /api2/json/version succeeds once the TLS handshake does).
func tlsFakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeCAFile writes the server's leaf certificate as a PEM trust anchor.
func writeCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	der := srv.Certificate().Raw
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if pemBytes == nil {
		t.Fatal("failed to PEM-encode server cert")
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

func baseProxmoxCfg(url string) ProxmoxConfig {
	return ProxmoxConfig{
		URL:   url,
		Token: "u@pam!t=secret",
		Node:  "pve01",
		VMID:  100,
		Kind:  ProxmoxKindQEMU,
	}
}

// (a) Default trust = system store. A self-signed PVE cert must NOT be
// trusted: Available fails closed.
func TestProxmoxTLS_SystemTrust_RejectsUntrusted(t *testing.T) {
	srv := tlsFakeServer(t)
	px, err := NewProxmox(baseProxmoxCfg(srv.URL))
	if err != nil {
		t.Fatalf("NewProxmox: %v", err)
	}
	if px.Available(context.Background()) {
		t.Fatal("expected Available=false against an untrusted self-signed cert (default must be secure)")
	}
}

// (b) Custom CA file = trust exactly that PEM. Verification succeeds.
func TestProxmoxTLS_CAFile_TrustsPinnedCert(t *testing.T) {
	srv := tlsFakeServer(t)
	cfg := baseProxmoxCfg(srv.URL)
	cfg.CAFile = writeCAFile(t, srv)
	px, err := NewProxmox(cfg)
	if err != nil {
		t.Fatalf("NewProxmox: %v", err)
	}
	if !px.Available(context.Background()) {
		t.Fatal("expected Available=true when the server cert is trusted via CAFile")
	}
}

// (c) InsecureSkipVerify = explicit opt-in. Verification is skipped AND a
// warning is logged.
func TestProxmoxTLS_InsecureSkipVerify_WorksAndWarns(t *testing.T) {
	srv := tlsFakeServer(t)
	var buf bytes.Buffer
	cfg := baseProxmoxCfg(srv.URL)
	cfg.InsecureSkipVerify = true
	cfg.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	px, err := NewProxmox(cfg)
	if err != nil {
		t.Fatalf("NewProxmox: %v", err)
	}
	if !px.Available(context.Background()) {
		t.Fatal("expected Available=true when InsecureSkipVerify is set")
	}
	if !strings.Contains(buf.String(), "verification is DISABLED") {
		t.Fatalf("expected a warning about disabled verification, got: %q", buf.String())
	}
}

// InsecureSkipVerify takes precedence over CAFile.
func TestProxmoxTLS_InsecurePrecedence(t *testing.T) {
	srv := tlsFakeServer(t)
	cfg := baseProxmoxCfg(srv.URL)
	cfg.CAFile = filepath.Join(t.TempDir(), "does-not-exist.pem")
	cfg.InsecureSkipVerify = true
	// CAFile is never read because InsecureSkipVerify wins; construction
	// must succeed despite the bogus path.
	px, err := NewProxmox(cfg)
	if err != nil {
		t.Fatalf("NewProxmox: %v", err)
	}
	if !px.Available(context.Background()) {
		t.Fatal("expected Available=true (insecure precedence)")
	}
}

// A missing CA file is a hard configuration error.
func TestProxmoxTLS_CAFile_MissingIsError(t *testing.T) {
	cfg := baseProxmoxCfg("https://pve.invalid:8006")
	cfg.CAFile = filepath.Join(t.TempDir(), "nope.pem")
	if _, err := NewProxmox(cfg); err == nil {
		t.Fatal("expected an error for a missing ca_file")
	}
}

// A CA file with no valid PEM certificates is a hard configuration error.
func TestProxmoxTLS_CAFile_GarbageIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	cfg := baseProxmoxCfg("https://pve.invalid:8006")
	cfg.CAFile = path
	if _, err := NewProxmox(cfg); err == nil {
		t.Fatal("expected an error for a ca_file with no valid certificates")
	}
}

// Sanity: the built TLS config always pins MinVersion >= TLS 1.2.
func TestProxmoxTLS_MinVersionPinned(t *testing.T) {
	for _, tc := range []ProxmoxConfig{
		baseProxmoxCfg("https://x:8006"),
		func() ProxmoxConfig { c := baseProxmoxCfg("https://x:8006"); c.InsecureSkipVerify = true; return c }(),
	} {
		got, err := proxmoxTLSConfig(tc)
		if err != nil {
			t.Fatalf("proxmoxTLSConfig: %v", err)
		}
		if got.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %d, want %d", got.MinVersion, tls.VersionTLS12)
		}
	}
	_ = x509.NewCertPool()
}
