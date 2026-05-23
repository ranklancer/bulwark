# Bulwark dashboard (web/)

Vite + React + TypeScript + Tailwind. The build artifact lives at
`../internal/api/ui-react/dist/` so the Go server picks it up via
`go:embed` — there's no separate "deploy the static files" step.

## Develop

```sh
cd web
npm install
npm run dev      # Vite dev server at http://localhost:5173
                 # /api/* requests are proxied to http://localhost:8080
```

In a second terminal, run `bulwark serve` (or `bulwark run`) on :8080
so the proxy has something to talk to.

## Build for embedding

```sh
cd web
npm ci           # use lockfile in CI; npm install during dev
npm run build    # emits ../internal/api/ui-react/dist/{index.html, assets/*}
```

Then `go build ./...` in the repo root picks up the freshly-built
artifact. CI runs both steps in `.github/workflows/ci.yml`.

## Why a placeholder dist?

`go:embed` fails the build when the embedded directory is missing. The
committed `internal/api/ui-react/dist/index.html` placeholder lets
`go build` succeed for operators without a Node toolchain — they get
the legacy vanilla dashboard at `/`. After `npm run build` the React
SPA mounts at `/` and the legacy dashboard moves to `/legacy/`.

## Bundle-size budget

```sh
npm run build
npm run perf:check
```

Fails when any single chunk exceeds 200 KB gzipped, when the entry +
vendor chunks combined exceed 350 KB gzipped, or when total CSS
exceeds 40 KB gzipped. Override the defaults with
`BULWARK_PERF_PER_CHUNK_GZ_KB`, `BULWARK_PERF_ENTRY_GZ_KB`, or
`BULWARK_PERF_CSS_GZ_KB` env vars when ratcheting the gate down.

CI runs `perf:check` on every PR.

## Lighthouse CI

```sh
# In repo root: build the binary once
go build -o bulwark ./cmd/bulwark

cd web
npm run build
BULWARK_BIN=../bulwark npm run perf:lighthouse
```

LHCI spins up `bulwark serve --no-docker --listen :8080` (anonymous
mode — never use this outside CI / dev), runs a desktop-preset
Lighthouse pass against `http://localhost:8080/`, and asserts:

| Metric | Threshold |
|---|---:|
| LCP | < 1500 ms |
| Total transfer | < 500 KB |
| CLS | < 0.1 |

The CI workflow runs this best-effort (`continue-on-error: true`)
while we accumulate a stable baseline; it'll flip to a hard gate
once the numbers settle. LHCI ships via `npx` so it doesn't bloat
`package-lock.json` with Puppeteer + Chromium.
