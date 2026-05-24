# Phase 2 — Quick wins (perf/quick-wins)

Branch carries five commits, each landed separately so revert / bisect
is clean. All scope is server-side: no SPA build changes.

| # | Commit subject | Files touched |
|---|---|---|
| 1 | `perf: Phase 2 plan doc` | `docs/perf-phase-2-plan.md` |
| 2 | `perf: gzip+brotli compression middleware for UI routes` | `internal/api/compress.go` (new), `internal/api/compress_test.go` (new), `internal/api/server.go`, `go.mod`, `go.sum` |
| 3 | `perf: modulepreload Link header on the SPA index` | `internal/api/server.go`, `internal/api/server_test.go` |
| 4 | `perf: regression tests for SPA cache headers` | `internal/api/server_test.go` |
| 5 | `perf: drop access log for healthz/readyz probes` | `internal/api/server.go`, `internal/api/server_test.go` |

## What each commit ships

### 2 — Compression
- New `compressMiddleware(next)` in `internal/api/compress.go`.
  Negotiates `Accept-Encoding`, picks brotli when both `br` and
  `gzip` are advertised, falls back to gzip, else passes through
  uncompressed. Always emits `Vary: Accept-Encoding` so HTTP caches
  keep per-encoding entries.
- Wraps the SPA index handler + the `/assets/*` file server +
  the legacy dashboard handler. Deliberately NOT applied to
  `/api/v1/*` in this phase: the SSE stream at `/api/v1/events`
  would break under buffered encoding, and the api-response
  win is a separate scope (follow-up if requested).
- Adds `github.com/andybalholm/brotli v1.2.1` — the daemon's
  first non-stdlib runtime dep beyond `gopkg.in/yaml.v3`.
- Expected wire-size impact on the SPA's 260 KB bundle:
  ~78 KB gzip, ~62 KB brotli.

### 3 — Modulepreload
- New `preloadLinkHeader(indexHTML)` parses the Vite-emitted
  entry-script `src` once at startup and returns an HTTP
  `Link: </assets/index-XXX.js>; rel=modulepreload` value.
- The SPA's `GET /` handler emits the header so the browser
  begins fetching the entry chunk in parallel with HTML parse.
- Saves one RTT on cold loads; no measurable cost on warm loads.

### 4 — Cache regression tests
- New focused assertions in `server_test.go` covering:
  - SPA index gets `Cache-Control: no-store`.
  - Hashed assets get `Cache-Control: public, max-age=31536000, immutable`.
  - Headers are present in the response before the body bytes start.
- No production behaviour change — the headers are already correct
  per the Phase 1 audit. The tests guard against regression.

### 5 — Healthz log fast path
- `withLogging` skips the per-request `slog.Info("api: handled", …)`
  call when the path is `/healthz` or `/readyz`.
- These probes typically fire every 5–30 seconds in production; on
  long-running daemons they dominate the access log without carrying
  any operator-relevant signal. Real errors (probe taking too long,
  returning non-200) still surface via the application-level health
  checks.

## What this phase deliberately does NOT do

- Compression on `/api/v1/*` — SSE at `/api/v1/events` is the
  blocker. Plan a follow-up that either pre-buffers the JSON
  endpoints or splits the routing tree.
- A per-asset bundle visualiser — that's Phase 3.
- Lazy-loading routes — Phase 3.
- CI bundle-size gate — Phase 4.

## Verification

After all five commits land:

```sh
go vet ./...
go test -race -count=1 ./...
bash scripts/check-pii.sh
```

Manual smoke (any operator with the binary built):

```sh
# Confirms the wire shrinks under compression
curl -s -o /dev/null -w "%{size_download}\n" -H 'Accept-Encoding: gzip' \
  http://localhost:8080/assets/index-XXX.js
curl -s -o /dev/null -w "%{size_download}\n" -H 'Accept-Encoding: br' \
  http://localhost:8080/assets/index-XXX.js
curl -s -o /dev/null -w "%{size_download}\n" \
  http://localhost:8080/assets/index-XXX.js

# Confirms the modulepreload hint is emitted on the SPA root
curl -sI http://localhost:8080/ | grep -i ^link

# Confirms healthz no longer floods the log
bulwark serve --api.listen=:8080 &
for i in $(seq 1 20); do curl -s http://localhost:8080/healthz; done
grep -c 'path=/healthz' bulwark.log   # should print 0
```
