package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Identity is the result of a successful Authenticate call. For anonymous
// access User is empty and Groups is nil.
type Identity struct {
	User   string
	Groups []string
}

// IsAnonymous reports whether the identity carries no authenticated user.
func (i Identity) IsAnonymous() bool { return i.User == "" }

// HasGroup reports whether the identity is in the named group.
func (i Identity) HasGroup(g string) bool {
	if g == "" {
		return true
	}
	for _, x := range i.Groups {
		if x == g {
			return true
		}
	}
	return false
}

// AuthError lets implementations communicate the appropriate HTTP status
// alongside a public-safe message. http.Error would conflate 401 vs 403,
// which we want distinct (missing creds vs. forbidden user).
type AuthError struct {
	Status int
	Msg    string
}

func (e *AuthError) Error() string { return e.Msg }

// unauthorized / forbidden are the canonical errors implementations return.
func unauthorized(msg string) error { return &AuthError{Status: http.StatusUnauthorized, Msg: msg} }
func forbidden(msg string) error    { return &AuthError{Status: http.StatusForbidden, Msg: msg} }

// Authenticator gates access to the state API and dashboard. Every
// implementation either returns a valid Identity (which may be anonymous)
// or an *AuthError describing why the request was rejected.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// AnonymousAuth allows every request and returns an empty Identity.
// Production deployments should NOT use this when the listener is reachable
// from beyond localhost — `bulwark serve` and `bulwark run` warn at startup
// when this combination is detected.
type AnonymousAuth struct{}

func (AnonymousAuth) Authenticate(_ *http.Request) (Identity, error) {
	return Identity{}, nil
}

// BearerAuth requires a single shared secret on the Authorization: Bearer
// header (or X-Bulwark-Token as an alias). Comparison is constant-time so
// authorized vs. unauthorized requests can't be distinguished by timing.
//
// This is the right model for machine-to-machine callers (DIUN, scripts)
// but it provides no per-user audit trail. For human users use ForwardProxyAuth.
type BearerAuth struct {
	Token string
	// User is recorded in the returned Identity; useful for audit logs
	// when the bearer is shared by a small known set of operators.
	// Default: "bearer".
	User string
}

func (b BearerAuth) Authenticate(r *http.Request) (Identity, error) {
	if b.Token == "" {
		// Misconfiguration — refuse rather than silently allowing.
		return Identity{}, unauthorized("server has BearerAuth configured with no token")
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.Header.Get("X-Bulwark-Token")
	}
	if tok == "" {
		return Identity{}, unauthorized("missing Authorization: Bearer header")
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(b.Token)) != 1 {
		return Identity{}, unauthorized("invalid bearer token")
	}
	user := b.User
	if user == "" {
		user = "bearer"
	}
	return Identity{User: user}, nil
}

// ForwardProxyAuth trusts identity headers set by a reverse proxy that
// terminates SSO/MFA upstream — Authelia, Authentik, Pomerium, oauth2-proxy,
// and Cloudflare Access all use this pattern.
//
// The headers are honoured ONLY when the request's TCP origin
// (r.RemoteAddr) falls inside one of the TrustedProxies CIDRs. Any request
// from outside is rejected with 403 before the headers are read, which
// neutralises header-spoofing attacks.
//
// Default header names (UserHeader, GroupsHeader) match Authelia /
// oauth2-proxy ("Remote-User", "Remote-Groups"); Authentik uses the same
// names in its proxy outpost out of the box.
type ForwardProxyAuth struct {
	// TrustedProxies is the set of CIDR blocks whose connections are
	// allowed to set identity headers. Empty = no requests trusted —
	// every call returns 403, which is the correct fail-closed default.
	TrustedProxies []*net.IPNet

	// UserHeader is the request header that carries the authenticated
	// username. Default: "Remote-User".
	UserHeader string

	// GroupsHeader is the request header that carries the user's groups,
	// comma-separated. Default: "Remote-Groups".
	GroupsHeader string

	// RequiredGroup, when non-empty, restricts access to users in this
	// group. Useful when your IdP issues groups for org/role separation
	// and you want only e.g. "ops" or "admins" to see Bulwark.
	RequiredGroup string
}

// NewForwardProxyAuth parses a list of CIDR strings and returns a configured
// ForwardProxyAuth. Returns an error for malformed CIDRs so misconfiguration
// surfaces at startup, not at first request.
func NewForwardProxyAuth(trustedCIDRs []string, userHeader, groupsHeader, requiredGroup string) (*ForwardProxyAuth, error) {
	nets := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, s := range trustedCIDRs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("forward-proxy: bad CIDR %q: %w", s, err)
		}
		nets = append(nets, n)
	}
	if userHeader == "" {
		userHeader = "Remote-User"
	}
	if groupsHeader == "" {
		groupsHeader = "Remote-Groups"
	}
	return &ForwardProxyAuth{
		TrustedProxies: nets,
		UserHeader:     userHeader,
		GroupsHeader:   groupsHeader,
		RequiredGroup:  requiredGroup,
	}, nil
}

func (f *ForwardProxyAuth) Authenticate(r *http.Request) (Identity, error) {
	if !f.peerTrusted(r) {
		return Identity{}, forbidden("request not from a trusted proxy")
	}
	user := r.Header.Get(f.UserHeader)
	if user == "" {
		return Identity{}, unauthorized(fmt.Sprintf("missing %s header from trusted proxy", f.UserHeader))
	}
	groups := parseGroups(r.Header.Get(f.GroupsHeader))
	id := Identity{User: user, Groups: groups}
	if f.RequiredGroup != "" && !id.HasGroup(f.RequiredGroup) {
		return Identity{}, forbidden(fmt.Sprintf("user %q is not in required group %q", user, f.RequiredGroup))
	}
	return id, nil
}

// peerTrusted reports whether r.RemoteAddr falls inside any configured
// TrustedProxies CIDR. Empty TrustedProxies means no peer is trusted.
func (f *ForwardProxyAuth) peerTrusted(r *http.Request) bool {
	if len(f.TrustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// IPv6 without port (rare) or malformed — fail closed.
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range f.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseGroups splits a header value into individual group names. Authelia
// and oauth2-proxy both use comma-separated; Authentik allows comma- or
// whitespace-separated. Be liberal in what we accept.
func parseGroups(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// identityKey is the unexported context key under which the resolved
// Identity is stored on authenticated requests.
type identityKey struct{}

// IdentityFromContext returns the Identity attached to ctx by the auth
// middleware, or the zero Identity if none was present.
func IdentityFromContext(ctx context.Context) Identity {
	if v, ok := ctx.Value(identityKey{}).(Identity); ok {
		return v
	}
	return Identity{}
}

// withIdentity returns a request whose context carries the resolved Identity.
// Handlers can read it via IdentityFromContext when they need to record
// who initiated an action (decisions, snapshot deletes, etc.).
func withIdentity(r *http.Request, id Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
}

// authMiddleware wraps next with the configured Authenticator and surfaces
// AuthErrors as the appropriate HTTP status. Anonymous identities (from
// AnonymousAuth) pass through with the empty Identity attached.
func authMiddleware(auth Authenticator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.Authenticate(r)
		if err != nil {
			status := http.StatusUnauthorized
			var ae *AuthError
			if errors.As(err, &ae) && ae.Status != 0 {
				status = ae.Status
			}
			http.Error(w, err.Error(), status)
			return
		}
		next(w, withIdentity(r, id))
	}
}
