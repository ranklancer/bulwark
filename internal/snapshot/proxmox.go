package snapshot

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProxmoxKind is the resource type the backend snapshots: a fully-
// virtualised VM (qemu) or a Linux container (lxc).
type ProxmoxKind string

const (
	ProxmoxKindQEMU ProxmoxKind = "qemu"
	ProxmoxKindLXC  ProxmoxKind = "lxc"
)

// ProxmoxConfig configures the Proxmox VE API backend. URL is the
// Proxmox API base; Token is the full "user@realm!tokenid=secret"
// string as issued by the Proxmox UI's API Tokens page.
type ProxmoxConfig struct {
	URL   string
	Token string
	Node  string
	VMID  int
	Kind  ProxmoxKind

	// TLS trust is resolved in this order (default = SECURE):
	//   1. InsecureSkipVerify=true -> verification disabled (dev escape
	//      hatch; logs a warning). Takes precedence when set.
	//   2. CAFile != "" -> trust exactly the PEM bundle at this path (the
	//      recommended path for a private CA such as step-ca).
	//   3. otherwise -> the host system trust store.
	CAFile             string
	InsecureSkipVerify bool

	// Logger receives operational warnings (e.g. when TLS verification is
	// disabled). Optional; nil silences them.
	Logger *slog.Logger

	// HTTPClient overrides the constructed *http.Client. Tests inject
	// an httptest server's client here.
	HTTPClient *http.Client

	// Now lets tests freeze time when composing snapshot names.
	Now func() time.Time
}

// ProxmoxBackend implements snapshot.Backend by calling the Proxmox VE
// REST API at /api2/json/nodes/{node}/{kind}/{vmid}/snapshot. Auth is
// via an API token in the PVEAPIToken header (the headed token format
// avoids the cookie-based login flow's CSRF token dance).
//
// Conceptual model: this backend snapshots the *whole VM/LXC* that
// Bulwark runs inside of, not individual Docker containers. The
// "target" passed to Snapshot/Restore/Destroy is ignored — the
// configured VMID is the snapshot subject for every call. This makes
// sense because Proxmox can't snapshot a single container's volume in
// isolation: snapshots are taken at the disk image level, which
// covers the entire VM at once.
//
// Bulwark's container-level rollback still runs alongside the Proxmox
// snapshot; the Proxmox snapshot is the "we tried everything else and
// the whole machine is wedged" escape hatch.
type ProxmoxBackend struct {
	cfg     ProxmoxConfig
	baseAPI string
}

// NewProxmox constructs a backend from the given config. The function
// validates URL + Token + Node + VMID; missing or malformed values
// return a clear error so the operator sees the misconfiguration at
// startup, not at the first failed apply.
func NewProxmox(cfg ProxmoxConfig) (*ProxmoxBackend, error) {
	if cfg.URL == "" {
		return nil, errors.New("proxmox: url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("proxmox: url is malformed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxmox: url scheme must be http or https, got %q", u.Scheme)
	}
	if !strings.Contains(cfg.Token, "=") || !strings.Contains(cfg.Token, "!") {
		return nil, errors.New("proxmox: token must be 'user@realm!tokenid=secret'")
	}
	if cfg.Node == "" {
		return nil, errors.New("proxmox: node is required")
	}
	if cfg.VMID <= 0 {
		return nil, errors.New("proxmox: vmid must be > 0")
	}
	kind := cfg.Kind
	if kind == "" {
		kind = ProxmoxKindQEMU
	}
	if kind != ProxmoxKindQEMU && kind != ProxmoxKindLXC {
		return nil, fmt.Errorf("proxmox: kind must be 'qemu' or 'lxc', got %q", kind)
	}
	cfg.Kind = kind
	if cfg.HTTPClient == nil {
		tlsCfg, err := proxmoxTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		cfg.HTTPClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	baseAPI := strings.TrimRight(cfg.URL, "/") + "/api2/json"
	return &ProxmoxBackend{cfg: cfg, baseAPI: baseAPI}, nil
}

func (p *ProxmoxBackend) Name() string { return "proxmox" }

// Available probes the API by hitting /version. We deliberately don't
// require the token to verify (some installs scope the token tightly
// enough that /version is not authorised); a 401 from this path is
// still "the backend is reachable" — Snapshot will surface auth
// failures with a clearer per-call error.
func (p *ProxmoxBackend) Available(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseAPI+"/version", nil)
	if err != nil {
		return false
	}
	p.setAuth(req)
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Anything 2xx is fine; some scoped tokens get 401 from /version
	// but can still snapshot — accept both.
	return resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusUnauthorized
}

// Snapshot creates a snapshot named bulwark-<label>-<timestamp>. The
// target argument is ignored (see ProxmoxBackend doc); the configured
// VMID is the subject. Returns the snapshot name as the opaque id so
// Restore/Destroy can address it later.
func (p *ProxmoxBackend) Snapshot(ctx context.Context, target, label string) (string, error) {
	name := snapshotName(label, p.cfg.Now())
	// Proxmox snapshot names are constrained: ASCII letters/digits/
	// underscores/hyphens, max 40 chars. Convert any dots from
	// sanitizeLabel into underscores and truncate.
	pvName := strings.ReplaceAll(name, ".", "_")
	if len(pvName) > 40 {
		pvName = pvName[:40]
	}

	body := url.Values{}
	body.Set("snapname", pvName)
	body.Set("description", "bulwark pre-update snapshot")

	path := fmt.Sprintf("/nodes/%s/%s/%d/snapshot", p.cfg.Node, p.cfg.Kind, p.cfg.VMID)
	if err := p.postForm(ctx, path, body); err != nil {
		return "", fmt.Errorf("proxmox: snapshot: %w", err)
	}
	return pvName, nil
}

// Restore rolls the configured VMID back to the snapshot named id.
// Proxmox's rollback endpoint also reboots the VM; LXC restarts.
func (p *ProxmoxBackend) Restore(ctx context.Context, id string) error {
	path := fmt.Sprintf("/nodes/%s/%s/%d/snapshot/%s/rollback",
		p.cfg.Node, p.cfg.Kind, p.cfg.VMID, url.PathEscape(id))
	if err := p.postForm(ctx, path, url.Values{}); err != nil {
		return fmt.Errorf("proxmox: rollback: %w", err)
	}
	return nil
}

// Destroy removes the snapshot named id.
func (p *ProxmoxBackend) Destroy(ctx context.Context, id string) error {
	path := fmt.Sprintf("/nodes/%s/%s/%d/snapshot/%s",
		p.cfg.Node, p.cfg.Kind, p.cfg.VMID, url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, "DELETE", p.baseAPI+path, nil)
	if err != nil {
		return fmt.Errorf("proxmox: build delete: %w", err)
	}
	p.setAuth(req)
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxmox: delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return p.errorFromBody(resp)
	}
	return nil
}

// List returns Bulwark-created snapshots for the configured VMID. The
// target argument is ignored.
func (p *ProxmoxBackend) List(ctx context.Context, target string) ([]Snapshot, error) {
	path := fmt.Sprintf("/nodes/%s/%s/%d/snapshot", p.cfg.Node, p.cfg.Kind, p.cfg.VMID)
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseAPI+path, nil)
	if err != nil {
		return nil, fmt.Errorf("proxmox: build list: %w", err)
	}
	p.setAuth(req)
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxmox: list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, p.errorFromBody(resp)
	}
	var payload struct {
		Data []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			SnapTime    int64  `json:"snaptime"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("proxmox: decode list: %w", err)
	}
	out := make([]Snapshot, 0, len(payload.Data))
	for _, s := range payload.Data {
		// Proxmox returns a synthetic "current" entry — skip it.
		if s.Name == "current" {
			continue
		}
		label, when, ok := parseProxmoxSnapshotName(s.Name, s.SnapTime)
		if !ok {
			continue
		}
		out = append(out, Snapshot{
			ID:        s.Name,
			Target:    strconv.Itoa(p.cfg.VMID),
			Label:     label,
			CreatedAt: when,
		})
	}
	return out, nil
}

// postForm POSTs a urlencoded body and returns nil on 2xx, an
// API-error wrapping the body's `errors` field on non-2xx.
func (p *ProxmoxBackend) postForm(ctx context.Context, path string, body url.Values) error {
	req, err := http.NewRequestWithContext(ctx, "POST", p.baseAPI+path, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.setAuth(req)
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return p.errorFromBody(resp)
	}
	return nil
}

func (p *ProxmoxBackend) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "PVEAPIToken="+p.cfg.Token)
}

// errorFromBody renders a Proxmox API error envelope into a helpful
// Go error. PVE puts useful messages in the `errors` map; on plain
// HTTP failures the body may be empty.
func (p *ProxmoxBackend) errorFromBody(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	snippet := strings.TrimSpace(string(body))
	if snippet == "" {
		return fmt.Errorf("api returned %s", resp.Status)
	}
	return fmt.Errorf("api returned %s: %s", resp.Status, snippet)
}

// parseProxmoxSnapshotName extracts the Bulwark label from a Proxmox-
// stored snapshot name. We use parseSnapshotName for the prefix +
// timestamp logic, falling back to Proxmox's snaptime when our naming
// scheme is in play but the timestamp parse fails (paranoia for
// older snapshots).
func parseProxmoxSnapshotName(name string, snaptime int64) (label string, when time.Time, ok bool) {
	// Try Bulwark's standard parse first.
	if l, t, ok := parseSnapshotName(strings.ReplaceAll(name, "_", ".")); ok {
		return l, t, true
	}
	// Bulwark-prefixed but unparseable timestamp: trust the API's
	// snaptime field and fish the label out.
	if !strings.HasPrefix(name, labelPrefix+"-") {
		return "", time.Time{}, false
	}
	rest := strings.TrimPrefix(name, labelPrefix+"-")
	// Strip the trailing yyyymmddThhmmssZ-ish suffix if present.
	parts := strings.Split(rest, "-")
	if len(parts) > 1 {
		rest = strings.Join(parts[:len(parts)-1], "-")
	}
	return rest, time.Unix(snaptime, 0).UTC(), true
}

// proxmoxTLSConfig builds the client tls.Config from the trust options on
// cfg, defaulting to the secure system trust store. Order of precedence:
// InsecureSkipVerify (dev escape hatch, warns) > CAFile (private CA) >
// system store. MinVersion is pinned to TLS 1.2 in every mode.
func proxmoxTLSConfig(cfg ProxmoxConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cfg.InsecureSkipVerify:
		// Explicit, default-false operator opt-in. Never silent: warn so a
		// misconfiguration is visible in the logs.
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- documented, default-false operator opt-in; warns when enabled
		if cfg.Logger != nil {
			cfg.Logger.Warn("proxmox: TLS certificate verification is DISABLED (insecure_skip_verify=true) — do not use in production; prefer tls.ca_file for a private CA")
		}
	case cfg.CAFile != "":
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 -- operator-supplied trust anchor path from config
		if err != nil {
			return nil, fmt.Errorf("proxmox: read tls.ca_file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("proxmox: tls.ca_file %q contained no valid PEM certificates", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	default:
		// System trust store (RootCAs nil => host defaults).
	}
	return tlsCfg, nil
}
