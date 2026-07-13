package capture

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Shared HTTP-security primitives for API/DB-managed backends (Portainer, Komodo,
// …). Centralised so their TLS trust model, redirect/credential-downgrade guard,
// cleartext-base policy and SSRF connect-IP guard can never drift between adapters.

// managedTLSConfig builds a fail-closed-by-default TLS config (TLS 1.2 floor):
// system trust by default; a private CA via caFile; verification disabled only on
// an explicit, logged insecure opt-in. label prefixes log/error messages.
func managedTLSConfig(label string, insecureSkipVerify bool, caFile string, logger *slog.Logger) (*tls.Config, error) {
	if logger == nil {
		logger = slog.Default()
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case insecureSkipVerify:
		logger.Warn(label + ": TLS certificate verification DISABLED (insecure_skip_verify); prefer ca_file")
		c.InsecureSkipVerify = true // #nosec G402 -- explicit operator opt-in, off by default, logged
	case strings.TrimSpace(caFile) != "":
		pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured CA bundle path
		if err != nil {
			return nil, fmt.Errorf("%s: read ca_file: %w", label, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: ca_file %s contained no valid PEM certificates", label, caFile)
		}
		c.RootCAs = pool
	}
	return c, nil
}

// checkCleartextBase refuses a cleartext http:// base URL to a NON-loopback host
// unless the operator opts in (loopback is always allowed). Credentials would
// otherwise travel unencrypted. The opt-in path logs a warning.
func checkCleartextBase(label string, u *url.URL, allowInsecureHTTP bool, logger *slog.Logger) error {
	if u.Scheme != "http" || isLoopbackHost(u.Hostname()) {
		return nil
	}
	if !allowInsecureHTTP {
		return fmt.Errorf("%s: refusing a cleartext http:// base URL to non-loopback host %q — credentials would be sent unencrypted; use https, or set allow_insecure_http: true to override", label, u.Host)
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn(label+": cleartext http base URL in use; credentials are sent unencrypted", "host", u.Host)
	return nil
}

// refuseCrossHostRedirect blocks any redirect that changes host OR scheme relative
// to the origin. The scheme check refuses an https->http downgrade that would
// re-send credential headers over cleartext to the same host.
func refuseCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	orig := via[0].URL
	if req.URL.Host != orig.Host {
		return fmt.Errorf("managed http: refusing cross-host redirect to %q", req.URL.Host)
	}
	if req.URL.Scheme != orig.Scheme {
		return fmt.Errorf("managed http: refusing redirect changing scheme %q->%q (credential-downgrade guard)", orig.Scheme, req.URL.Scheme)
	}
	if len(via) >= 10 {
		return errors.New("managed http: too many redirects")
	}
	return nil
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// guardedTransport builds an http.Transport whose dialer rejects link-local,
// multicast and unspecified connect IPs after DNS resolution — containing
// DNS-rebinding SSRF to those targets (e.g. 169.254.x cloud metadata), which are
// never a legitimate managed-backend host. Loopback and RFC1918 stay allowed:
// self-hosted orchestrators commonly live on a private/loopback address.
func guardedTransport(tlsCfg *tls.Config) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: blockDangerousConnectIP}
	return &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           d.DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// blockDangerousConnectIP runs on the resolved IP just before connect.
func blockDangerousConnectIP(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("managed http: refusing to connect to disallowed address %s (SSRF guard: link-local/multicast/unspecified)", ip)
	}
	return nil
}
