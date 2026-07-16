package api

import (
	"net/http"
	"net/url"
	"strings"
)

// CSRFConfig controls the cross-site-request-forgery defense applied to
// state-mutating endpoints (POST/DELETE/PUT/PATCH on /api/v1/*).
//
// The defense is intentionally simple — three layered checks. Browsers
// can't forge any of them from a cross-origin context without the user's
// explicit cooperation:
//
//  1. Method gate: only mutating methods are protected.
//  2. Sec-Fetch-Site: when present (modern browsers), require "same-origin"
//     or "none" (the latter for explicit address-bar requests). Cross-site
//     and same-site fetches are rejected.
//  3. Origin allow-list: when Sec-Fetch-Site is missing (curl, older
//     browsers), require Origin to match one of the configured allow-list
//     hosts, or be absent entirely (curl/scripts that don't send Origin).
//
// Server-to-server callers (DIUN webhook, scripts) are unaffected by either
// check because they don't run in a browser security context — Sec-Fetch-Site
// is a browser-only header and Origin is browser-set.
type CSRFConfig struct {
	// AllowedOrigins lists the http/https origins permitted to issue
	// cross-origin POSTs. Hostnames or full origins ("https://bulwark.example.com").
	// Empty list means "same-origin only" — the most restrictive choice.
	AllowedOrigins []string

	// TrustNoOrigin, when true, allows requests with NO Origin header to
	// pass (curl, simple scripts). When false, every mutation must have
	// either Sec-Fetch-Site=same-origin OR a recognised Origin. Defaults
	// to true so machine-to-machine bearer auth works without forcing
	// callers to fake a browser header.
	TrustNoOrigin bool
}

// DefaultCSRFConfig returns the standard "same-origin browsers, also allow
// header-less scripts" stance. It's the right fit for Bulwark's mix of
// dashboard + scripts + DIUN.
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{TrustNoOrigin: true}
}

// csrfMiddleware enforces the CSRF policy on the wrapped handler.
// Non-mutating methods pass through unchanged.
func csrfMiddleware(cfg CSRFConfig, allowedHosts []string, next http.Handler) http.Handler {
	hostSet := make(map[string]struct{}, len(cfg.AllowedOrigins)+len(allowedHosts))
	for _, o := range append(cfg.AllowedOrigins, allowedHosts...) {
		o = strings.TrimSpace(strings.ToLower(o))
		if o == "" {
			continue
		}
		hostSet[o] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mutatingMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if err := checkCSRF(r, cfg, hostSet); err != nil {
			http.Error(w, "csrf: "+err.Error(), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfMiddlewareFunc is the HandlerFunc-shaped variant for inline use.
func csrfMiddlewareFunc(cfg CSRFConfig, allowedHosts []string, next http.HandlerFunc) http.HandlerFunc {
	wrapped := csrfMiddleware(cfg, allowedHosts, next)
	return wrapped.ServeHTTP
}

func mutatingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// checkCSRF returns nil when the request is allowed, or a public-safe error
// describing why it was rejected. Error messages are deliberately generic so
// they don't tell an attacker which check failed.
func checkCSRF(r *http.Request, cfg CSRFConfig, allowedHosts map[string]struct{}) error {
	// 1. Sec-Fetch-Site is the strongest signal when present.
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return nil
	case "":
		// fall through to Origin check
	default:
		// "cross-site" or "same-site" — neither acceptable for a
		// state-mutating call.
		return errCSRFCrossOrigin
	}

	// 2. Origin allow-list.
	originRaw := r.Header.Get("Origin")
	if originRaw == "" {
		// No Origin: typically curl/scripts. Honour the policy switch.
		if cfg.TrustNoOrigin {
			return nil
		}
		return errCSRFCrossOrigin
	}

	originURL, err := url.Parse(originRaw)
	if err != nil {
		return errCSRFCrossOrigin
	}
	candidate := strings.ToLower(originURL.Host)
	full := strings.ToLower(originRaw)

	// Same-host as the request? That's same-origin in everything but name.
	if candidate != "" && strings.EqualFold(candidate, r.Host) {
		return nil
	}
	// On the explicit allow-list?
	if _, ok := allowedHosts[full]; ok {
		return nil
	}
	if _, ok := allowedHosts[candidate]; ok {
		return nil
	}
	return errCSRFCrossOrigin
}

// errCSRFCrossOrigin is the single public error every check returns. The
// message is intentionally generic so it doesn't help an attacker probe
// which layer (Sec-Fetch-Site, Origin allow-list, content type) failed.
var errCSRFCrossOrigin = csrfRejectedError("cross-origin or untrusted request")

type csrfRejectedError string

func (e csrfRejectedError) Error() string { return string(e) }
