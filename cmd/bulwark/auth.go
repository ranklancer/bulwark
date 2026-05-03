package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/api"
	"github.com/bulwark-docker/bulwark/internal/config"
)

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
