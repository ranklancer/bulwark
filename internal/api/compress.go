package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// compressMiddleware compresses responses with brotli or gzip when the
// client advertises support. Brotli wins when both encodings are
// advertised, giving the SPA bundle a ~20% smaller wire size than gzip
// alone. Vary: Accept-Encoding is always set so HTTP caches keep
// per-encoding entries.
//
// Designed for static-ish handlers (the SPA index, the asset file
// server). Streaming endpoints — notably the SSE stream at
// /api/v1/events — must NOT be wrapped: the encoder buffers data
// until it's worth emitting a block, which defeats the point of SSE.
func compressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")

		encoding := negotiateEncoding(r.Header.Get("Accept-Encoding"))
		if encoding == "" {
			next.ServeHTTP(w, r)
			return
		}

		cw := newCompressingWriter(w, encoding)
		defer cw.Close()
		next.ServeHTTP(cw, r)
	})
}

// negotiateEncoding picks an encoding from a client's Accept-Encoding
// header. Returns "br", "gzip", or "" (no compression).
//
// q-values are intentionally ignored. Real browsers send both br + gzip
// without weights, and bulwark's only other consumers are curl/scripts
// which usually omit the header entirely. Honouring q properly would
// add a real parser for negligible benefit.
func negotiateEncoding(acceptEncoding string) string {
	if acceptEncoding == "" {
		return ""
	}
	var hasGzip, hasBr bool
	for _, p := range strings.Split(acceptEncoding, ",") {
		token := strings.TrimSpace(p)
		if i := strings.IndexByte(token, ';'); i >= 0 {
			token = strings.TrimSpace(token[:i])
		}
		switch strings.ToLower(token) {
		case "br":
			hasBr = true
		case "gzip":
			hasGzip = true
		}
	}
	switch {
	case hasBr:
		return "br"
	case hasGzip:
		return "gzip"
	default:
		return ""
	}
}

// compressingWriter wraps an http.ResponseWriter and encodes the body
// with the configured codec. The encoder is constructed lazily inside
// WriteHeader so handlers that short-circuit (e.g. http.NotFound on a
// missing asset) don't allocate one.
type compressingWriter struct {
	http.ResponseWriter
	encoding    string
	wroteHeader bool
	encoder     io.WriteCloser
}

func newCompressingWriter(w http.ResponseWriter, encoding string) *compressingWriter {
	return &compressingWriter{ResponseWriter: w, encoding: encoding}
}

func (c *compressingWriter) WriteHeader(code int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true

	// Respect an upstream handler that's already encoded its own body.
	if c.ResponseWriter.Header().Get("Content-Encoding") != "" {
		c.encoding = ""
		c.ResponseWriter.WriteHeader(code)
		return
	}

	h := c.ResponseWriter.Header()
	h.Set("Content-Encoding", c.encoding)
	// Compressed length is unknown up front; chunked transfer takes over.
	h.Del("Content-Length")
	c.ResponseWriter.WriteHeader(code)

	switch c.encoding {
	case "br":
		c.encoder = brotli.NewWriter(c.ResponseWriter)
	case "gzip":
		c.encoder = gzip.NewWriter(c.ResponseWriter)
	}
}

func (c *compressingWriter) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if c.encoder == nil {
		return c.ResponseWriter.Write(p)
	}
	return c.encoder.Write(p)
}

// Close flushes + closes the encoder, if one was created. The middleware
// defers this so the response is finalised even when the handler returns
// without explicitly closing the writer.
func (c *compressingWriter) Close() error {
	if c.encoder != nil {
		return c.encoder.Close()
	}
	return nil
}
