package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/api"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/scheduler"
)

// buildRegistryAuth turns the loaded YAML registries block into a
// concrete registry.Authenticator. Returns nil when no auth source is
// configured so the caller can leave Client.Auth zero and pull from
// public registries unchanged.
//
// Resolution order is composite: explicit YAML hosts first, then the
// optional Docker config fallback. nil-safe on a nil config (returns nil).
func buildRegistryAuth(cfg *config.Config, logger *slog.Logger) registry.Authenticator {
	if cfg == nil {
		return nil
	}
	// nil-safe: a caller (e.g. manifestClientFor) may pass no logger.
	if logger == nil {
		logger = slog.Default()
	}
	var sources []registry.Authenticator

	if len(cfg.Registries.Hosts) > 0 {
		m := make(registry.MapAuth, len(cfg.Registries.Hosts))
		for host, c := range cfg.Registries.Hosts {
			m[host] = registry.Credentials{
				Username:      c.Username,
				Password:      c.Password,
				IdentityToken: c.IdentityToken,
			}
		}
		sources = append(sources, m)
		logger.Info("registries: yaml host credentials loaded",
			"hosts", len(cfg.Registries.Hosts))
	}

	if cfg.Registries.UseDockerConfig {
		sources = append(sources, &registry.DockerConfigAuth{
			Path:          cfg.Registries.DockerConfigPath,
			ResolveHelper: registry.DefaultExecHelper,
		})
		logger.Info("registries: docker config fallback enabled",
			"path", cfg.Registries.DockerConfigPath)
	}

	if len(sources) == 0 {
		return nil
	}
	return registry.CompositeAuth{Auths: sources}
}

// hooksRoot pulls the configured Hooks.HooksRoot from the loaded YAML, or
// returns "" when no config was supplied. Centralised here so scan.go and
// run.go don't drift apart.
func hooksRoot(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.Hooks.HooksRoot
}

// buildDIUNHMAC returns a configured *api.HMACScheme when api.diun.hmac_secret
// is set, or nil to leave the DIUN handler in bearer-only mode. Centralised
// so serve.go and run.go can't accidentally diverge.
func buildDIUNHMAC(cfg *config.Config) *api.HMACScheme {
	if cfg == nil || cfg.API.DIUN.HMACSecret == "" {
		return nil
	}
	return api.NewHMACScheme([]byte(cfg.API.DIUN.HMACSecret))
}

// parseMaintenanceWindows reads schedule.maintenance_windows from the
// loaded config and parses each one. Errors are logged but do not block
// startup — a misconfigured single window shouldn't take the daemon
// offline; the operator gets a clear log line and the affected window
// is dropped.
func parseMaintenanceWindows(cfg *config.Config, logger *slog.Logger) []scheduler.Window {
	if cfg == nil {
		return nil
	}
	out := make([]scheduler.Window, 0, len(cfg.Schedule.MaintenanceWindows))
	for i, mw := range cfg.Schedule.MaintenanceWindows {
		w, err := scheduler.ParseWindow(mw.Start, mw.End, mw.Days)
		if err != nil {
			logger.Warn("schedule: ignoring invalid maintenance window",
				"index", i, "start", mw.Start, "end", mw.End, "err", err)
			continue
		}
		out = append(out, w)
	}
	return out
}

// buildAuthenticator translates the loaded YAML auth block into a concrete
// api.Authenticator. The resolution order — and the reasons for it:
//
//  1. Explicit api.auth.type wins, period. If a user typed it, honour it.
//  2. With type empty, fall back to api.diun.token (or the --diun-token
//     flag) as a bearer secret if one is set. This preserves Phase 6
//     behaviour: the same shared secret protects DIUN and the state API.
//  3. Otherwise return AnonymousAuth, with a stderr warning when the
//     listener might be reachable from beyond loopback.
//
// All AuthConfig validation has already happened in config.Load → Validate;
// here we trust the values and fail clearly only on construction errors
// (e.g. malformed CIDRs that slipped past validate).
func buildAuthenticator(cfg *config.Config, fallbackBearer string, logger *slog.Logger) (api.Authenticator, error) {
	if cfg == nil {
		// No config file passed (`bulwark serve --listen :8080` with no
		// --config). Use the fallback bearer if one was given on the
		// command line, else anonymous.
		if fallbackBearer != "" {
			return api.BearerAuth{Token: fallbackBearer}, nil
		}
		return api.AnonymousAuth{}, nil
	}

	t := strings.ToLower(strings.TrimSpace(cfg.API.Auth.Type))
	switch t {
	case "forward-proxy":
		fp, err := api.NewForwardProxyAuth(
			cfg.API.Auth.TrustedProxies,
			cfg.API.Auth.UserHeader,
			cfg.API.Auth.GroupsHeader,
			cfg.API.Auth.RequiredGroup,
		)
		if err != nil {
			return nil, fmt.Errorf("api.auth: %w", err)
		}
		logger.Info("api: forward-proxy auth configured",
			"trusted_proxies", cfg.API.Auth.TrustedProxies,
			"user_header", fp.UserHeader,
			"required_group", cfg.API.Auth.RequiredGroup,
		)
		return fp, nil

	case "bearer":
		token := cfg.API.Auth.Token
		if token == "" {
			token = fallbackBearer
		}
		if token == "" {
			return nil, fmt.Errorf("api.auth.type=bearer but no api.auth.token (or --diun-token) is set")
		}
		logger.Info("api: bearer auth configured")
		return api.BearerAuth{Token: token}, nil

	case "", "none":
		// Legacy implicit-bearer behaviour: when api.diun.token is set
		// and no explicit auth.type is configured, use it for the state
		// API too. Maintains the Phase 6 single-secret model.
		if t == "" && fallbackBearer != "" {
			logger.Info("api: bearer auth configured (from api.diun.token)")
			return api.BearerAuth{Token: fallbackBearer}, nil
		}
		logger.Warn("api: anonymous access — bind to localhost or put behind a trusted reverse proxy")
		return api.AnonymousAuth{}, nil
	}

	// Validate() should have caught everything else; defensive belt and braces.
	return nil, fmt.Errorf("api.auth.type=%q is not supported (validation should have caught this)", t)
}

// isLoopbackListen reports whether listen binds only the loopback interface.
// A bare ":8080", "0.0.0.0:8080", "[::]:8080" or "*" binds all interfaces and
// is treated as non-loopback. A host we can't parse as an IP is treated
// conservatively as non-loopback so the secure default errs toward refusing.
func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		host = strings.TrimSpace(listen)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	switch host {
	case "", "0.0.0.0", "::", "*":
		return false
	case "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// enforceAnonymousBinding implements Bulwark's secure-by-default posture for
// the control surface: an anonymous (api.auth.type=none) API may bind only the
// loopback interface. On any non-loopback bind it refuses to start unless the
// operator has explicitly set api.auth.allow_anonymous=true (the documented
// "auth is terminated at a trusted reverse proxy" escape hatch). Non-anonymous
// authenticators always pass.
func enforceAnonymousBinding(auth api.Authenticator, listen string, cfg *config.Config, logger *slog.Logger) error {
	if _, anon := auth.(api.AnonymousAuth); !anon {
		return nil
	}
	if isLoopbackListen(listen) {
		return nil
	}
	if cfg != nil && cfg.API.Auth.AllowAnonymous {
		logger.Warn("api: anonymous access on a non-loopback listener — allowed only because api.auth.allow_anonymous=true; ensure a trusted reverse proxy terminates authentication",
			"listen", listen)
		return nil
	}
	return fmt.Errorf("api.auth.type=none refuses to bind non-loopback address %q: an anonymous control surface would be exposed. Set api.auth.type=bearer or forward-proxy, bind to 127.0.0.1, or set api.auth.allow_anonymous=true to override", listen)
}

// enforceSnapshotApply applies the same secure-by-default posture to
// auto-apply: with --apply enabled but no snapshot backend configured,
// auto-acted SAFE updates would not be filesystem-recoverable. Bulwark
// refuses --apply in that case unless snapshots.allow_apply_without_backend
// is explicitly set. A nil config (no --config file) is treated as
// backend=none.
func enforceSnapshotApply(apply bool, cfg *config.Config) error {
	if !apply {
		return nil
	}
	backend := ""
	allow := false
	if cfg != nil {
		backend = strings.ToLower(strings.TrimSpace(cfg.Snapshots.Backend))
		allow = cfg.Snapshots.AllowApplyWithoutBackend
	}
	switch backend {
	case "", "none":
		if allow {
			return nil
		}
		return fmt.Errorf("--apply refuses to run without a snapshot backend: auto-applied updates would not be filesystem-recoverable. Configure snapshots.backend (zfs/btrfs/lvm/restic/volume), or set snapshots.allow_apply_without_backend=true to accept container-level rollback only")
	default:
		return nil
	}
}
