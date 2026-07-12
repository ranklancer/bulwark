// Package config parses the YAML configuration file that drives Bulwark's
// behaviour. The on-disk format is documented in configs/bulwark.example.yaml.
//
// The package supports environment-variable substitution: any `${VAR}` token
// in a string-valued field is replaced with the value of the environment
// variable VAR before parsing. This lets users keep secrets out of the YAML
// file ("token: ${HASS_TOKEN}").
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// Config is the root of the on-disk configuration.
type Config struct {
	Docker         DockerConfig         `yaml:"docker"`
	Schedule       ScheduleConfig       `yaml:"schedule"`
	Classification ClassificationConfig `yaml:"classification"`
	Snapshots      SnapshotsConfig      `yaml:"snapshots"`
	Health         HealthConfig         `yaml:"health"`
	Hooks          HooksConfig          `yaml:"hooks"`
	Notifications  NotificationsConfig  `yaml:"notifications"`
	Overrides      Overrides            `yaml:"overrides"`
	Exclude        Exclude              `yaml:"exclude"`
	API            APIConfig            `yaml:"api"`
	Registries     RegistriesConfig     `yaml:"registries"`
	Logging        LoggingConfig        `yaml:"logging"`
	Security       SecurityConfig       `yaml:"security"`
	Verify         VerifyConfig         `yaml:"verify"`
	Capture        CaptureConfig        `yaml:"capture"`
	Sources        []SourceConfig       `yaml:"sources"`
}

// SecurityConfig is the opt-in CVE/security-urgency block. When Enabled is
// false (the default) Bulwark behaves exactly as before. It adds a
// security-urgency axis to decisions without touching the stability gate.
type SecurityConfig struct {
	Enabled bool `yaml:"enabled"`
	// SeverityThreshold is the minimum severity of a CLOSED CVE that counts
	// toward urgency: "critical" (default) or "high" (critical+high).
	SeverityThreshold string `yaml:"severity_threshold"`
	// AutoApplyUrgentSafe lets CRITICAL-closing SAFE updates auto-apply on a
	// tighter schedule (bypassing the maintenance window). Off by default.
	AutoApplyUrgentSafe bool            `yaml:"auto_apply_urgent_safe"`
	CVESource           CVESourceConfig `yaml:"cve_source"`
}

// CVESourceConfig selects the pluggable vulnerability backend.
type CVESourceConfig struct {
	Type  string            `yaml:"type"` // trivy | grype (via the cve.ScanSource provider factory; docker-scout / registry are reserved extension points)
	Trivy TrivySourceConfig `yaml:"trivy"`
	Grype TrivySourceConfig `yaml:"grype"` // same report_dir/server_url shape
}

// TrivySourceConfig configures a filesystem-report backend. ReportDir points
// at a directory of JSON reports (`trivy image --format json` or
// `grype -o json`); ServerURL is reserved for a future server mode.
type TrivySourceConfig struct {
	ReportDir string `yaml:"report_dir"`
	ServerURL string `yaml:"server_url"`
}

// RegistriesConfig controls how Bulwark authenticates against
// non-public container registries. UseDockerConfig=true makes the
// daemon read ~/.docker/config.json (auths block, credHelpers,
// credsStore) the same way `docker login` populates it. Hosts holds
// explicit per-registry overrides applied BEFORE the docker-config
// fallback so YAML always wins when both are present.
type RegistriesConfig struct {
	UseDockerConfig  bool                              `yaml:"use_docker_config"`
	DockerConfigPath string                            `yaml:"docker_config_path"`
	Hosts            map[string]RegistryHostCredential `yaml:"hosts"`
}

// RegistryHostCredential is a single host's static credentials. Either
// IdentityToken (OAuth2 refresh token) or Username + Password are set.
type RegistryHostCredential struct {
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	IdentityToken string `yaml:"identity_token"`
}

// HooksConfig configures the pre/post/rollback hook subsystem. The single
// field today is HooksRoot — when set, only scripts inside that directory
// are allowed to run. Any path supplied via container labels that escapes
// the root is rejected. Empty HooksRoot keeps the legacy behavior where
// any executable path is honored.
type HooksConfig struct {
	HooksRoot string `yaml:"hooks_root"`
}

type DockerConfig struct {
	Host string `yaml:"host"`
	TLS  struct {
		Enabled bool   `yaml:"enabled"`
		Cert    string `yaml:"cert"`
		Key     string `yaml:"key"`
		CA      string `yaml:"ca"`
	} `yaml:"tls"`
}

type ScheduleConfig struct {
	Check              string              `yaml:"check"`
	ScanInterval       string              `yaml:"scan_interval"`
	MaintenanceWindows []MaintenanceWindow `yaml:"maintenance_windows"`
}

type MaintenanceWindow struct {
	Start string   `yaml:"start"` // HH:MM, 24-hour
	End   string   `yaml:"end"`
	Days  []string `yaml:"days"`
}

type ClassificationConfig struct {
	DefaultRisk       string       `yaml:"default_risk"`
	BreakingKeywords  []string     `yaml:"breaking_keywords"`
	MigrationKeywords []string     `yaml:"migration_keywords"`
	SecurityKeywords  []string     `yaml:"security_keywords"`
	TrustedRebuilders []string     `yaml:"trusted_rebuilders"`
	Policies          PolicyConfig `yaml:"policies"`
	ChangelogMaxChars int          `yaml:"changelog_max_chars"`
}

type PolicyConfig struct {
	Patch       string `yaml:"patch"`
	Minor       string `yaml:"minor"`
	Major       string `yaml:"major"`
	Digest      string `yaml:"digest"`
	Latest      string `yaml:"latest"`
	LSIORebuild string `yaml:"lsio_rebuild"`
	Prerelease  string `yaml:"prerelease"`
}

type SnapshotsConfig struct {
	Backend string `yaml:"backend"`
	// AllowApplyWithoutBackend permits `--apply` when Backend is
	// "none". Default false: auto-applied SAFE updates would not be
	// filesystem-recoverable without a snapshot backend, so Bulwark
	// refuses --apply unless this is explicitly set.
	AllowApplyWithoutBackend bool `yaml:"allow_apply_without_backend"`
	ZFS                      struct {
		Datasets []string `yaml:"datasets"`
	} `yaml:"zfs"`
	Btrfs struct {
		Subvolumes []string `yaml:"subvolumes"`
	} `yaml:"btrfs"`
	Restic struct {
		Repository   string `yaml:"repository"`
		PasswordFile string `yaml:"password_file"`
	} `yaml:"restic"`
	Proxmox struct {
		// URL is the Proxmox VE API base, e.g. "https://pve.local:8006".
		URL string `yaml:"url"`
		// Token is the full PVE API token in the format
		// "user@realm!tokenid=secret". Use ${ENV_VAR} substitution so the
		// secret never appears in the yaml file directly.
		Token string `yaml:"token"`
		// Node is the cluster node name the target VM/LXC runs on
		// (e.g. "pve01"). Required because the snapshot API is per-node.
		Node string `yaml:"node"`
		// VMID is the numeric id of the VM or LXC Bulwark snapshots
		// before each apply. Typically the VM/LXC bulwark itself runs in.
		VMID int `yaml:"vmid"`
		// Kind is "qemu" (default) or "lxc". Determines whether the API
		// path is /nodes/{node}/qemu/... or /nodes/{node}/lxc/...
		Kind string `yaml:"kind"`
		// TLS configures how the PVE endpoint's certificate is trusted.
		// Default (empty) uses the host system trust store — correct for a
		// PVE endpoint fronted by a public/proper CA.
		TLS struct {
			// CAFile is a PEM bundle path to trust a private issuing CA
			// (e.g. step-ca). The recommended way to trust a self-signed
			// or private-CA PVE endpoint.
			CAFile string `yaml:"ca_file"`
			// InsecureSkipVerify disables certificate verification
			// entirely. Default false. Dev/escape-hatch only; the daemon
			// logs a warning when it is enabled. Prefer ca_file.
			InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
		} `yaml:"tls"`
		// InsecureTLS is DEPRECATED: use tls.insecure_skip_verify. When
		// true it is still honoured (mapped to tls.insecure_skip_verify)
		// with a deprecation warning, for backward compatibility.
		InsecureTLS bool `yaml:"insecure_tls"`
	} `yaml:"proxmox"`
	Retention struct {
		KeepLast int `yaml:"keep_last"`
		KeepDays int `yaml:"keep_days"`
	} `yaml:"retention"`
}

type HealthConfig struct {
	Timeout     string `yaml:"timeout"`
	Interval    string `yaml:"interval"`
	Threshold   int    `yaml:"threshold"`
	GracePeriod string `yaml:"grace_period"`
}

type NotificationsConfig struct {
	HomeAssistant HAConfig        `yaml:"homeassistant"`
	Slack         SlackConfig     `yaml:"slack"`
	Discord       DiscordConfig   `yaml:"discord"`
	SMTP          SMTPConfig      `yaml:"smtp"`
	Ntfy          NtfyConfig      `yaml:"ntfy"`
	Shoutrrr      ShoutrrrConfig  `yaml:"shoutrrr"`
	Generic       []GenericConfig `yaml:"generic"`
	Digest        DigestConfig    `yaml:"digest"`
}

// NtfyConfig configures the ntfy push-notification integration. ServerURL
// points at the publish endpoint (e.g. https://ntfy.sh or a self-hosted
// instance); Topic is the topic name (no leading slash); Token is the
// optional bearer access token. Use ${ENV_VAR} substitution for the
// token so secrets stay out of the committed yaml.
type NtfyConfig struct {
	Enabled   bool   `yaml:"enabled"`
	ServerURL string `yaml:"server_url"`
	Topic     string `yaml:"topic"`
	Token     string `yaml:"token"`
	MinLevel  string `yaml:"min_level"`
}

// GenericConfig configures a single arbitrary HTTP webhook channel. Multiple
// channels are supported (each can have its own URL, headers, and threshold)
// to cover the common case of "Home Assistant + n8n + an internal dashboard".
type GenericConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Name     string            `yaml:"name"`
	URL      string            `yaml:"url"`
	Method   string            `yaml:"method"`
	Headers  map[string]string `yaml:"headers"`
	MinLevel string            `yaml:"min_level"`
}

type HAConfig struct {
	Enabled  bool          `yaml:"enabled"`
	URL      string        `yaml:"url"`
	Token    string        `yaml:"token"`
	Safe     HANotifyLevel `yaml:"safe"`
	Review   HANotifyLevel `yaml:"review"`
	Breaking HANotifyLevel `yaml:"breaking"`
	Rollback HANotifyLevel `yaml:"rollback"`
}

type HANotifyLevel struct {
	Persistent bool `yaml:"persistent"`
	Push       bool `yaml:"push"`
	Critical   bool `yaml:"critical"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
	MinLevel   string `yaml:"min_level"`
}

type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	MinLevel   string `yaml:"min_level"`
}

type SMTPConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	TLS      bool     `yaml:"tls"`
}

type ShoutrrrConfig struct {
	Enabled bool     `yaml:"enabled"`
	URLs    []string `yaml:"urls"`
}

type DigestConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule"`
}

type Overrides struct {
	Stacks     map[string]Override `yaml:"stacks"`
	Containers map[string]Override `yaml:"containers"`
}

type Override struct {
	RiskOverride         string       `yaml:"risk_override"`
	Schedule             string       `yaml:"schedule"`
	PreUpdateHook        string       `yaml:"pre_update_hook"`
	PostUpdateHook       string       `yaml:"post_update_hook"`
	RollbackHook         string       `yaml:"rollback_hook"`
	HealthTimeout        string       `yaml:"health_timeout"`
	SnapshotDataset      string       `yaml:"snapshot_dataset"`
	ClassificationPolicy PolicyConfig `yaml:"classification_policy"`
}

type Exclude struct {
	Stacks     []string `yaml:"stacks"`
	Containers []string `yaml:"containers"`
	Images     []string `yaml:"images"`
}

type APIConfig struct {
	Enabled bool       `yaml:"enabled"`
	Listen  string     `yaml:"listen"`
	Auth    AuthConfig `yaml:"auth"`
	// DIUN configures the DIUN-compatibility webhook receiver mounted at
	// POST /api/v1/webhooks/diun. The endpoint is enabled whenever the
	// API server is enabled; the Token field optionally requires a
	// shared secret on each call.
	DIUN APIDIUNConfig `yaml:"diun"`
}

// AuthConfig configures authentication for the state API and embedded
// dashboard. Three types are supported:
//
//	none           anonymous access; safe only for localhost listeners
//	bearer         single shared-secret token (machine-to-machine; no MFA)
//	forward-proxy  trust identity headers from a reverse proxy that
//	               terminates SSO/MFA upstream (Authelia, Authentik,
//	               Pomerium, oauth2-proxy, Cloudflare Access)
//
// "basic", "oidc", "saml" etc. are NOT yet implemented. Setting them
// produces a startup error pointing at forward-proxy as the recommended
// path for SSO/MFA in homelab deployments.
type AuthConfig struct {
	Type string `yaml:"type"`

	// AllowAnonymous permits api.auth.type=none on a NON-loopback
	// listener. Default false: Bulwark refuses to start an anonymous
	// control surface on a public bind. Set true only when a trusted
	// reverse proxy terminates authentication in front of Bulwark.
	AllowAnonymous bool `yaml:"allow_anonymous"`

	// Token is the shared secret for type=bearer.
	Token string `yaml:"token"`

	// TrustedProxies lists CIDR blocks (10.0.0.0/8 etc.) whose connections
	// are allowed to set identity headers. Required for type=forward-proxy.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// UserHeader / GroupsHeader are the request headers from which the
	// authenticated user and groups are read. Defaults match the
	// Authelia/Authentik/oauth2-proxy convention: "Remote-User" and
	// "Remote-Groups" respectively.
	UserHeader   string `yaml:"user_header"`
	GroupsHeader string `yaml:"groups_header"`

	// RequiredGroup, when non-empty, restricts access to users in the
	// named group. The IdP populates GroupsHeader.
	RequiredGroup string `yaml:"required_group"`
}

type APIDIUNConfig struct {
	// Token is an optional shared secret. When set, requests must include
	// it via either `Authorization: Bearer <token>` or `X-Bulwark-Token`.
	Token string `yaml:"token"`

	// HMACSecret, when set, layers HMAC-SHA256 replay protection on top of
	// the bearer token. Each request must carry X-Bulwark-Timestamp and
	// X-Bulwark-Signature headers signing the body. DIUN can't natively
	// sign — point DIUN at the bulwark-diun-relay sidecar binary, and
	// point the relay at Bulwark with the same shared secret.
	HMACSecret string `yaml:"hmac_secret"`

	// DedupTTL controls per-event silencing when persistent state is
	// configured. Zero or empty disables dedup.
	DedupTTL string `yaml:"dedup_ttl"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads, expands env vars in, parses, validates, and returns a Config.
// If path is empty, Defaults() is returned.
func Load(path string) (*Config, error) {
	if path == "" {
		return Defaults(), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path: %w", err)
	}
	raw, err := os.ReadFile(abs) // #nosec G304 -- config file path from the operator/CLI
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", abs, err)
	}
	expanded, err := expandEnv(string(raw))
	if err != nil {
		return nil, err
	}

	cfg := Defaults()
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", abs, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}
	return cfg, nil
}

// Defaults returns a Config populated with the same defaults as
// configs/bulwark.example.yaml — usable without any user file present.
func Defaults() *Config {
	c := &Config{}
	c.Docker.Host = "unix:///var/run/docker.sock"
	c.Schedule.Check = "0 */6 * * *"
	c.Classification.DefaultRisk = "review"
	c.Classification.BreakingKeywords = nil // nil means use classifier defaults
	c.Classification.MigrationKeywords = nil
	c.Classification.SecurityKeywords = nil
	c.Classification.TrustedRebuilders = nil
	c.Classification.Policies = PolicyConfig{
		Patch: "safe", Minor: "review", Major: "breaking",
		Digest: "safe", Latest: "review",
		LSIORebuild: "safe", Prerelease: "review",
	}
	c.Classification.ChangelogMaxChars = 500
	c.Snapshots.Backend = "none"
	c.Snapshots.Retention.KeepLast = 5
	c.Snapshots.Retention.KeepDays = 30
	c.Health.Timeout = "120s"
	c.Health.Interval = "5s"
	c.Health.Threshold = 3
	c.Health.GracePeriod = "10s"
	c.API.Enabled = true
	c.API.Listen = ":8080"
	c.API.Auth.Type = "none"
	c.API.Auth.UserHeader = "Remote-User"
	c.API.Auth.GroupsHeader = "Remote-Groups"
	c.Logging.Level = "info"
	c.Logging.Format = "json"
	return c
}

// envVarRE matches `${VAR}` tokens for environment-variable substitution.
// We intentionally do not support `$VAR` (without braces) so YAML strings
// containing literal dollar signs are not silently rewritten.
var envVarRE = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)\}`)

// expandEnv replaces every `${VAR}` token in s with a resolved secret value.
// Resolution follows the Docker-secrets `_FILE` convention (see
// resolveSecretEnv): provide exactly one of VAR or VAR_FILE — setting both is
// rejected as ambiguous. An unset variable with no _FILE indirection is left
// as the literal `${VAR}` token, preserving prior behaviour. A both-set,
// unreadable, or empty _FILE fails closed with a non-nil error.
func expandEnv(s string) (string, error) {
	var firstErr error
	out := envVarRE.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		v, found, err := resolveSecretEnv(name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return m
		}
		if found {
			return v
		}
		return m
	})
	return out, firstErr
}

// Validate checks for inconsistent or unsupported settings. It is called by
// Load but is exposed for tests and tools.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("nil config")
	}
	if level := types.ParseRiskLevel(c.Classification.DefaultRisk); level == types.RiskUnknown {
		return fmt.Errorf("classification.default_risk %q is not safe/review/breaking", c.Classification.DefaultRisk)
	}
	for name, field := range map[string]string{
		"patch": c.Classification.Policies.Patch, "minor": c.Classification.Policies.Minor,
		"major": c.Classification.Policies.Major, "digest": c.Classification.Policies.Digest,
		"latest": c.Classification.Policies.Latest, "lsio_rebuild": c.Classification.Policies.LSIORebuild,
		"prerelease": c.Classification.Policies.Prerelease,
	} {
		if field == "" {
			continue
		}
		if level := types.ParseRiskLevel(field); level == types.RiskUnknown {
			return fmt.Errorf("classification.policies.%s %q is not safe/review/breaking", name, field)
		}
	}
	for stack, ov := range c.Overrides.Stacks {
		if ov.RiskOverride == "" {
			continue
		}
		if level := types.ParseRiskLevel(ov.RiskOverride); level == types.RiskUnknown {
			return fmt.Errorf("overrides.stacks.%s.risk_override %q is invalid", stack, ov.RiskOverride)
		}
	}
	for ctr, ov := range c.Overrides.Containers {
		if ov.RiskOverride == "" {
			continue
		}
		if level := types.ParseRiskLevel(ov.RiskOverride); level == types.RiskUnknown {
			return fmt.Errorf("overrides.containers.%s.risk_override %q is invalid", ctr, ov.RiskOverride)
		}
	}
	switch strings.ToLower(c.Snapshots.Backend) {
	case "", "none", "zfs", "btrfs", "lvm", "restic", "volume":
		// ok
	default:
		return fmt.Errorf("snapshots.backend %q is not a recognized backend", c.Snapshots.Backend)
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateSecurity(); err != nil {
		return err
	}
	if err := c.validateVerify(); err != nil {
		return err
	}
	if err := c.validateCapture(); err != nil {
		return err
	}
	return nil
}

// validateSecurity rejects a malformed security block at startup so an
// operator who thinks they enabled CVE intelligence doesn't silently get
// nothing. No-op when security.enabled is false.
func (c *Config) validateSecurity() error {
	if !c.Security.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(c.Security.SeverityThreshold)) {
	case "", "critical", "high":
	default:
		return fmt.Errorf("security.severity_threshold %q is not critical or high", c.Security.SeverityThreshold)
	}
	t := strings.ToLower(strings.TrimSpace(c.Security.CVESource.Type))
	var dir, srv string
	switch t {
	case "", "trivy":
		dir, srv = c.Security.CVESource.Trivy.ReportDir, c.Security.CVESource.Trivy.ServerURL
	case "grype":
		dir, srv = c.Security.CVESource.Grype.ReportDir, c.Security.CVESource.Grype.ServerURL
	default:
		return fmt.Errorf("security.cve_source.type %q is not supported (valid: trivy, grype)", c.Security.CVESource.Type)
	}
	// Server mode is not implemented yet (see cve.NewScanSource): a server_url
	// with no report_dir would silently disable the axis. Require report_dir.
	if dir == "" {
		if srv != "" {
			return fmt.Errorf("security.cve_source.%s.server_url is set but server mode is not implemented yet; provide report_dir", t)
		}
		return fmt.Errorf("security.cve_source requires report_dir when security.enabled=true")
	}
	return nil
}

// validateAuth rejects misconfigured api.auth blocks at startup so users
// don't get a silently-anonymous server when they think they've enabled
// a real auth scheme.
func (c *Config) validateAuth() error {
	t := strings.ToLower(strings.TrimSpace(c.API.Auth.Type))
	switch t {
	case "", "none":
		// fine — anonymous (matches the legacy default)
	case "bearer":
		// Token may be empty if api.diun.token is set; the Authenticator
		// builder falls back to that. Don't require it here.
	case "forward-proxy":
		if len(c.API.Auth.TrustedProxies) == 0 {
			return fmt.Errorf("api.auth.type=%q requires api.auth.trusted_proxies (CIDR list); without it every request would be rejected", t)
		}
	case "basic", "oidc", "saml":
		return fmt.Errorf("api.auth.type=%q is not yet implemented; for SSO/MFA put Bulwark behind a reverse proxy that terminates auth (Authelia, Authentik, Pomerium, oauth2-proxy) and use api.auth.type=forward-proxy with the proxy's CIDR in trusted_proxies", t)
	default:
		return fmt.Errorf("api.auth.type=%q is not recognized; valid values: none, bearer, forward-proxy", t)
	}
	return nil
}

// ClassifierConfig translates the YAML classification block into the form
// expected by the classifier package.
func (c *Config) ClassifierConfig() classifier.Config {
	policy := classifier.DefaultPolicy()
	apply := func(field string, slot *types.RiskLevel) {
		if field == "" {
			return
		}
		if level := types.ParseRiskLevel(field); level != types.RiskUnknown {
			*slot = level
		}
	}
	apply(c.Classification.Policies.Patch, &policy.Patch)
	apply(c.Classification.Policies.Minor, &policy.Minor)
	apply(c.Classification.Policies.Major, &policy.Major)
	apply(c.Classification.Policies.Digest, &policy.Digest)
	apply(c.Classification.Policies.Latest, &policy.Latest)
	apply(c.Classification.Policies.LSIORebuild, &policy.LSIORebuild)
	apply(c.Classification.Policies.Prerelease, &policy.Prerelease)

	if def := types.ParseRiskLevel(c.Classification.DefaultRisk); def != types.RiskUnknown {
		policy.Default = def
	}

	rebuilders := c.Classification.TrustedRebuilders
	if len(rebuilders) == 0 {
		rebuilders = nil // signal the classifier to use its built-in defaults
	}

	return classifier.Config{
		Policy: policy,
		Keywords: classifier.NewKeywordSet(
			c.Classification.BreakingKeywords,
			c.Classification.MigrationKeywords,
			c.Classification.SecurityKeywords,
		),
		TrustedRebuilders: rebuilders,
		ChangelogMaxChars: c.Classification.ChangelogMaxChars,
	}
}
