package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Credentials are the secrets used to authenticate against a registry.
// Either Username + Password (Basic auth, htpasswd-style) or
// IdentityToken (OAuth2 refresh token used by registries like GHCR) are
// populated; never both. Empty Credentials means anonymous.
type Credentials struct {
	Username      string
	Password      string
	IdentityToken string
}

// Empty reports whether the credentials carry no usable secret.
func (c Credentials) Empty() bool {
	return c.Username == "" && c.Password == "" && c.IdentityToken == ""
}

// Authenticator resolves credentials for a given registry host. The
// host is the bare DNS name as it appears in image references
// ("registry.example.com", "ghcr.io"), without scheme or path.
//
// Lookup returns (creds, true) when the host has known credentials, or
// (Credentials{}, false) when the host should be treated as anonymous.
// Implementations MUST NOT panic on unknown hosts.
type Authenticator interface {
	Lookup(host string) (Credentials, bool)
}

// MapAuth is a static authenticator backed by a host → Credentials map.
// Bulwark builds one of these from the YAML `registries.hosts` section.
type MapAuth map[string]Credentials

// Lookup implements Authenticator.
func (m MapAuth) Lookup(host string) (Credentials, bool) {
	if m == nil {
		return Credentials{}, false
	}
	if c, ok := m[host]; ok && !c.Empty() {
		return c, true
	}
	return Credentials{}, false
}

// CompositeAuth tries each underlying Authenticator in order; the first
// hit wins. nil entries are skipped, so callers can build the composite
// unconditionally and let unused sources stay zero-valued.
type CompositeAuth struct {
	Auths []Authenticator
}

// Lookup implements Authenticator.
func (c CompositeAuth) Lookup(host string) (Credentials, bool) {
	for _, a := range c.Auths {
		if a == nil {
			continue
		}
		if creds, ok := a.Lookup(host); ok {
			return creds, true
		}
	}
	return Credentials{}, false
}

// DockerConfigAuth reads credentials from a Docker CLI config file
// (typically ~/.docker/config.json). It supports:
//
//   - auths.<host>.auth: base64("user:pass") for direct Basic auth
//   - auths.<host>.identitytoken: OAuth2 refresh token
//   - credHelpers.<host>: a per-host credential helper binary
//   - credsStore: a default credential helper for all hosts not in
//     auths/credHelpers
//
// Credential helpers follow Docker's convention: they're binaries named
// "docker-credential-<helper>" that read the registry host on stdin
// and emit JSON {"Username": "...", "Secret": "..."} on stdout.
type DockerConfigAuth struct {
	// Path is the config.json location. Empty defaults to
	// $HOME/.docker/config.json (or %USERPROFILE%/.docker/config.json on
	// Windows, though Bulwark targets Linux).
	Path string

	// ResolveHelper invokes a credential helper. Production wires this
	// to execHelper; tests inject a stub. nil disables helper resolution
	// (auths-only mode).
	ResolveHelper func(helper, host string) (Credentials, error)
}

// dockerConfigFile mirrors the JSON shape Bulwark reads from
// ~/.docker/config.json. We deliberately ignore everything except the
// auth-related top-level keys.
type dockerConfigFile struct {
	Auths       map[string]dockerConfigAuthEntry `json:"auths"`
	CredsStore  string                           `json:"credsStore"`
	CredHelpers map[string]string                `json:"credHelpers"`
}

type dockerConfigAuthEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

// Lookup implements Authenticator. Resolution order:
//  1. credHelpers.<host> if set — invoke that helper and return its result
//  2. auths.<host> if set — decode the base64 "auth" field, or use the
//     identitytoken / username+password fields directly
//  3. credsStore if set — invoke the default helper as a last resort
//
// Returns ok=false when no source produces credentials. Errors invoking
// a credential helper are SWALLOWED (logged via the caller's logger
// when auth is plumbed into the client) rather than returned, because
// credential resolution is a non-fatal best-effort path.
func (d *DockerConfigAuth) Lookup(host string) (Credentials, bool) {
	if d == nil {
		return Credentials{}, false
	}
	cfg, err := d.loadConfig()
	if err != nil {
		return Credentials{}, false
	}

	// Per-host credential helper takes precedence so operators can pin
	// secrets-per-registry to specific stores.
	if helper := cfg.CredHelpers[host]; helper != "" && d.ResolveHelper != nil {
		if creds, err := d.ResolveHelper(helper, host); err == nil && !creds.Empty() {
			return creds, true
		}
	}

	if entry, ok := cfg.Auths[host]; ok {
		if creds, ok := decodeAuthEntry(entry); ok {
			return creds, true
		}
	}

	// Fallback: a global credsStore handles every host not explicitly
	// listed in auths or credHelpers.
	if cfg.CredsStore != "" && d.ResolveHelper != nil {
		if creds, err := d.ResolveHelper(cfg.CredsStore, host); err == nil && !creds.Empty() {
			return creds, true
		}
	}

	return Credentials{}, false
}

// loadConfig reads the JSON config from disk. Missing / unparsable files
// yield an empty config + error so the caller falls through.
func (d *DockerConfigAuth) loadConfig() (dockerConfigFile, error) {
	path := d.Path
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return dockerConfigFile{}, err
		}
		path = filepath.Join(home, ".docker", "config.json")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- docker config.json path from the operator environment
	if err != nil {
		return dockerConfigFile{}, err
	}
	var cfg dockerConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return dockerConfigFile{}, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return cfg, nil
}

// decodeAuthEntry pulls credentials out of one auths.<host> block. The
// "auth" field is base64-encoded "username:password" — we accept either
// that or the explicit username+password fields. identitytoken (used by
// registries that mint OAuth2 refresh tokens after login) wins over the
// classic Basic-auth fields when both are present.
func decodeAuthEntry(e dockerConfigAuthEntry) (Credentials, bool) {
	if e.IdentityToken != "" {
		return Credentials{IdentityToken: e.IdentityToken}, true
	}
	if e.Username != "" || e.Password != "" {
		return Credentials{Username: e.Username, Password: e.Password}, true
	}
	if e.Auth == "" {
		return Credentials{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(e.Auth)
	if err != nil {
		return Credentials{}, false
	}
	colon := bytes.IndexByte(raw, ':')
	if colon < 0 {
		return Credentials{}, false
	}
	return Credentials{
		Username: string(raw[:colon]),
		Password: string(raw[colon+1:]),
	}, true
}

// execHelper invokes a Docker credential helper as a subprocess. The
// helper is named "docker-credential-<helper>"; it reads the host on
// stdin and emits {"Username":"...","Secret":"..."} on stdout. Use
// this as DockerConfigAuth.ResolveHelper in production.
func execHelper(ctx context.Context, helper, host string) (Credentials, error) {
	cmd := exec.CommandContext(ctx, "docker-credential-"+helper, "get") // #nosec G204 -- helper name from operator docker config; exec argv, no shell
	cmd.Stdin = strings.NewReader(host)
	out, err := cmd.Output()
	if err != nil {
		return Credentials{}, fmt.Errorf("registry: helper %s: %w", helper, err)
	}
	var resp struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return Credentials{}, fmt.Errorf("registry: helper %s decode: %w", helper, err)
	}
	if resp.Username == "" && resp.Secret == "" {
		return Credentials{}, errors.New("registry: helper returned empty credentials")
	}
	// The "Username" field is sometimes the literal string
	// "<token>" — that's the Docker convention indicating the Secret
	// should be treated as an OAuth2 IdentityToken.
	if resp.Username == "<token>" {
		return Credentials{IdentityToken: resp.Secret}, nil
	}
	return Credentials{Username: resp.Username, Password: resp.Secret}, nil
}

// DefaultExecHelper is a context-bound wrapper around execHelper suitable
// for use as DockerConfigAuth.ResolveHelper. The 5-second timeout keeps
// a misconfigured helper (slow GUI prompt, network call) from stalling
// the daemon's startup.
func DefaultExecHelper(helper, host string) (Credentials, error) {
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	return execHelper(ctx, helper, host)
}

const helperTimeout = 5 * time.Second
