package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SessionCookieName is the cookie the dashboard reads/writes. Avoid
// renaming — bookmarked tabs and existing browser sessions keep working
// across deployments only as long as the name is stable.
const SessionCookieName = "bulwark_session"

// defaultSessionTTL is how long a freshly-issued session cookie stays
// valid. 12h matches the upper end of typical operator-on-call shifts;
// shorter would make the dashboard re-prompt mid-incident.
const defaultSessionTTL = 12 * time.Hour

// SessionScheme issues and verifies HMAC-signed session cookies. The
// secret is generated once per process start; sessions therefore do
// NOT survive a daemon restart by design — operators re-authenticate
// after upgrades. This keeps the on-disk surface small (no session
// table to clean up, no key rotation drama, no risk of secret leak via
// dump-of-disk).
//
// Cookie format: "<exp-unix-seconds>.<base64-hmac>" where the HMAC is
// SHA-256 of the exp string keyed by Secret. The whole value is opaque
// to the dashboard JS — it lives only in the HttpOnly cookie.
type SessionScheme struct {
	Secret []byte
	TTL    time.Duration
	Now    func() time.Time
}

// NewSessionScheme returns a SessionScheme whose Secret is freshly drawn
// from crypto/rand. ttl=0 picks the 12-hour default. Errors here are
// fatal — we'd rather refuse to start than issue predictable cookies.
func NewSessionScheme(ttl time.Duration) (*SessionScheme, error) {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("api: generate session secret: %w", err)
	}
	return &SessionScheme{Secret: secret, TTL: ttl}, nil
}

// Issue generates a fresh signed session value and returns it along
// with its expiry time. The caller wraps the value in BuildCookie.
func (s *SessionScheme) Issue() (value string, expires time.Time) {
	now := s.now()
	exp := now.Add(s.TTL)
	payload := strconv.FormatInt(exp.Unix(), 10)
	sig := s.sign(payload)
	return payload + "." + sig, exp
}

// Verify reports whether the given cookie value is valid + unexpired.
// Constant-time compare on the HMAC defends against signature-leak
// timing attacks.
func (s *SessionScheme) Verify(value string) bool {
	if s == nil || value == "" {
		return false
	}
	dot := strings.IndexByte(value, '.')
	if dot <= 0 || dot == len(value)-1 {
		return false
	}
	payload, sig := value[:dot], value[dot+1:]
	expUnix, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}
	if s.now().Unix() > expUnix {
		return false
	}
	expected := s.sign(payload)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1
}

func (s *SessionScheme) sign(payload string) string {
	mac := hmac.New(sha256.New, s.Secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *SessionScheme) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// BuildCookie wraps a session value in an *http.Cookie ready for
// http.SetCookie. The cookie is HttpOnly (no JS access — XSS can't
// extract it) and SameSite=Lax (rejects cross-site POSTs but allows
// top-level navigation). Secure is set when the request arrived over
// TLS; reverse-proxy deployments that terminate TLS in front of
// Bulwark should also set X-Forwarded-Proto and trust it (operator's
// responsibility to configure their proxy).
func (s *SessionScheme) BuildCookie(value string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie returns a deletion cookie — same name, empty value,
// MaxAge=-1. Set this in the response to a logout request so the
// browser drops its copy.
func ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// CookieOrInnerAuth lets a session cookie satisfy authentication for
// human users while machine clients (DIUN, scripts) continue to use
// the configured Inner Authenticator (typically BearerAuth or
// ForwardProxyAuth).
//
// Resolution: a valid session cookie wins immediately and returns
// Identity{User: "session"}. On no/expired/invalid cookie, the request
// passes through to Inner whose error response is returned verbatim.
type CookieOrInnerAuth struct {
	Inner    Authenticator
	Sessions *SessionScheme
}

// Authenticate implements Authenticator.
func (a CookieOrInnerAuth) Authenticate(r *http.Request) (Identity, error) {
	if a.Sessions != nil {
		if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
			if a.Sessions.Verify(c.Value) {
				return Identity{User: "session"}, nil
			}
		}
	}
	if a.Inner == nil {
		return Identity{}, unauthorized("no inner authenticator configured")
	}
	return a.Inner.Authenticate(r)
}

// isSecureRequest reports whether the connection — as the browser
// sees it — is HTTPS. Two paths:
//
//   - Direct TLS termination by Bulwark: r.TLS != nil.
//   - TLS-terminating reverse proxy (nginx, Traefik, Caddy,
//     Cloudflare): the proxy advertises the original scheme via
//     X-Forwarded-Proto. We honour the leftmost value (per RFC 7239
//     this is the original client's protocol).
//
// Used to decide whether session cookies get the Secure flag. A
// spoofed X-Forwarded-Proto: https on a plain-HTTP request causes
// Bulwark to issue a Secure cookie that modern browsers refuse to
// accept on non-HTTPS responses (RFC 6265bis), so the worst case is
// a failed login on a misconfigured client — not credential theft.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		return false
	}
	leftmost := strings.TrimSpace(strings.SplitN(proto, ",", 2)[0])
	return strings.EqualFold(leftmost, "https")
}

// ErrSessionsDisabled is returned by the session endpoints when no
// SessionScheme was wired at construction time. Surfaces as 404 to
// keep the endpoint indistinguishable from a missing route to scanners.
var ErrSessionsDisabled = errors.New("api: sessions are not enabled")
