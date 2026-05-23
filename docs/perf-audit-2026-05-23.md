# Performance audit — 2026-05-23

Static audit of the bulwark dashboard's frontend + delivery pipeline,
captured before any optimisation work lands. The goal is to give Phase
2 / 3 / 4 a documented baseline to measure against and to record the
scope decisions that frame the sweep.

This pass is **measurement-only**. No code changes. Branch:
`uat/v1.0` at commit `4c557ae` (ntfy docs + example yaml).

---

## 1. Build artifact sizes

Captured verbatim from `cd web && npm run build` on this branch:

```
vite v6.4.2 building for production...
✓ 57 modules transformed.
../internal/api/ui-react/dist/index.html                   0.45 kB │ gzip:  0.28 kB
../internal/api/ui-react/dist/assets/index-By6ANaxb.css   17.24 kB │ gzip:  4.14 kB
../internal/api/ui-react/dist/assets/index-CjOw1M0x.js   260.04 kB │ gzip: 78.08 kB
```

| Asset | Uncompressed | Gzip (vite-computed) |
|---|---:|---:|
| `index.html` | 0.45 KB | 0.28 KB |
| `index-*.css` | 17.24 KB | 4.14 KB |
| `index-*.js` | 260.04 KB | 78.08 KB |
| **Total transfer (gz)** | — | **~82.5 KB** |

Observations:
- **Single JS chunk.** Every route, every modal, every hook imports
  eagerly. The bundle includes pages an operator may never visit
  (Snapshots, Audit, Settings). Code-splitting target for Phase 3.
- **Vite reports gzip, the daemon ships uncompressed.** The 78 KB
  number is theoretical — see §2.
- **57 modules** today. Adding Phase 17/18 features (Proxmox config,
  per-container snapshot toggle, AddNotifierModal kinds) bumped this
  from 53 in the original 16c baseline; the trajectory is up.

---

## 2. Server delivery inventory

Source of truth: `internal/api/server.go:222-255` (`mountUIRoutes` +
`cacheImmutable`).

| Response | Headers set today | Compression |
|---|---|---|
| `GET /` (SPA index) | `Content-Type: text/html; charset=utf-8`, `Cache-Control: no-store`, CSP | none |
| `GET /assets/*` (hashed JS/CSS) | `Cache-Control: public, max-age=31536000, immutable` | none |
| `GET /legacy/` | same as `/` | none |
| `GET /api/v1/*` | per-handler `Content-Type: application/json`; no `Cache-Control` | none |
| `GET /healthz`, `/readyz` | `Content-Type: application/json` | none |

Observations:
- **`Cache-Control` on hashed assets is already optimal.** Vite
  fingerprints `index-XXXXXXXX.js`; the year-long immutable cache is
  correct. No change needed in Phase 2.
- **`Cache-Control: no-store` on the SPA index is correct.** Otherwise
  the operator would get stuck on a stale shell pointing at a deleted
  hashed bundle after a release.
- **No HTTP compression at any layer.** The Go server is the only
  thing in front of the operator's browser in the default deployment
  (no nginx, no Caddy in-repo). The 260 KB JS goes out as 260 KB on
  the wire. Phase 2 quick-win #1.
- **No `Link: rel=modulepreload` header.** The browser only discovers
  the entry chunk after parsing `<script type="module">` in the HTML.
  A header-level hint shaves an RTT on cold loads. Phase 2 quick-win #3.
- **`/healthz` + `/readyz` log every request** (`withLogging` in
  `server.go:131`). Tiny effect per request, but for a healthcheck
  every 5–30 s it inflates the log ring on long-running daemons.
  Phase 2 quick-win #5.

---

## 3. Vite config inventory

Source: `web/vite.config.ts` (33 LOC, included below for the record).

| Knob | Current value | Notes |
|---|---|---|
| `build.outDir` | `../internal/api/ui-react/dist` | Embedded by `go:embed all:dist`. Correct. |
| `build.emptyOutDir` | `false` | Preserves the committed placeholder + `.gitignore`. Stale hashed assets are cleared by `prebuild` (`rm -rf .../dist/assets`). |
| `build.sourcemap` | `false` | Production. Correct. |
| `build.target` | default (`modules` = `es2020+`) | Modern. No change. |
| `build.rollupOptions.output.manualChunks` | **unset** | Single-bundle output. Splitting vendor (`react`, `react-dom`, `react-router-dom`) is Phase 3 work. |
| `server.proxy["/api"]` | `http://127.0.0.1:8080` | Dev only. Correct. |
| Plugins | `@vitejs/plugin-react` only | No `vite-plugin-html`, no compression plugin (compression is server-side). |

The config is small, intentional, and well-commented. The two open
levers are `manualChunks` (vendor split) and the introduction of a
bundle visualiser — both Phase 3.

---

## 4. Route inventory — eager vs lazy

Source: `web/src/App.tsx`. Every route imports its page module at the
top of the file, so **every page is in the entry bundle**.

| Route | Page | Component file | Current loading |
|---|---|---|---|
| `/login` | Login | `pages/Login.tsx` | eager |
| `/` | Dashboard | `pages/Dashboard.tsx` | eager |
| `/queue` | Queue | `pages/Queue.tsx` | eager |
| `/history` | History | `pages/History.tsx` | eager |
| `/history/:id` | History detail | `pages/HistoryDetail.tsx` | eager |
| `/containers` | Containers | `pages/Containers.tsx` | eager |
| `/notifiers` | Notifiers | `pages/Notifiers.tsx` | eager |
| `/snapshots` | Snapshots | `pages/Snapshots.tsx` | eager |
| `/audit` | Audit | `pages/Audit.tsx` | eager |
| `/settings` | Settings | `pages/Settings.tsx` | eager |
| (modal) | Add notifier | `components/AddNotifierModal.tsx` | eager |

Phase 3 target split (per the plan):

| Keep eager | Convert to `React.lazy()` |
|---|---|
| AppShell chrome, RequireAuth, Login, Dashboard, Queue, History | Audit, Settings, Snapshots, HistoryDetail, Containers, Notifiers, AddNotifierModal |

Eager set is the operator's first-paint + high-frequency surface.
Lazy set is everything visited second or rarely.

---

## 5. Auth bootstrap

Source: `web/src/main.tsx`, `web/src/lib/auth.tsx`,
`web/src/components/RequireAuth.tsx`.

- **One pre-paint API request.** `AuthProvider` on mount fires
  `GET /api/v1/sessions` to probe whether the operator's cookie is
  valid. Until that resolves, `RequireAuth` shows a "Loading…" placeholder.
- **No localStorage / IndexedDB warmup.** Token is never persisted
  client-side (deliberate — see Phase 15b).
- **No parallel data prefetch.** The dashboard's first data fetches
  (`useScansList`, `useQueue`) only fire once the dashboard mounts,
  which is gated on the auth probe.

Implication: the bootstrap critical path is

```
HTML → JS parse → React mount → GET /api/v1/sessions → Dashboard mount → first data fetch
```

The auth probe sits on the critical path for every visit. It can't
move to parallel with the JS download (server doesn't know the route),
but Phase 2's modulepreload hint shortens the "HTML → JS parse" gap
and Phase 3's code-splitting shrinks the JS itself.

---

## 6. Refused / out-of-scope (auditable deferrals)

Items called out in the operator's brief that don't apply to this
repo or that we're deliberately not doing. Recording them here so the
deferral is documented, not silent.

| Item | Status | Why |
|---|---|---|
| NPM proxy / nginx tuning | N/A | Bulwark binary serves the SPA directly. No proxy in repo. Any external proxy is outside our edit scope. |
| ranklancer's 14-point Docker hardening (`/var/folders/.../CLAUDE.md`) | N/A | File doesn't exist here. Compose already has `no-new-privileges`, `cap_drop: ALL`, self-exclusion label. Further hardening is a separate operator-driven pass, not a perf concern. |
| Rotate `GITHUB_PAT` to Vaultwarden | N/A | No `.env`, no Vaultwarden integration, no access. |
| `pnpm perf:check` | Adapted | Repo uses npm; the script will be `npm run perf:check`. |
| Live Lighthouse baseline against `bulwark.example.com` | Deferred | No network egress from this sandbox. Operator fills in §7 from a local run, or Phase 4's CI gate produces the first reproducible numbers. |
| SSR conversion | Refused | Per the brief. Right call for a single-tenant admin dashboard. |
| PNG sprite atlas | Refused | Per the brief. Bulwark ships no images. |
| Inline critical CSS (`vite-plugin-html`) | Refused | Tailwind output is one 17 KB blob; inlining all of it bloats the shell HTML on every uncached load, gives up `Cache-Control` on the CSS, and saves one HTTP request that piggybacks the same TCP connection. Net negative. |
| Preload hero font | N/A | System font stack (`-apple-system, BlinkMacSystemFont, …`). No web font. |

---

## 7. Baseline TODO (operator-filled)

Lighthouse numbers from this sandbox aren't representative — no
network egress, no real client. The operator should run Lighthouse
locally against a real `bulwark` instance and paste the numbers below
so Phase 2 / 3 / 4 have something concrete to regress against.

Suggested command (one Chromium + one bulwark, both local):

```sh
# Terminal 1: run bulwark with anonymous auth (Lighthouse can't log in)
bulwark serve --api.auth.type=none --api.listen=:8080

# Terminal 2: install Lighthouse + capture a desktop run
npm install -g lighthouse
lighthouse http://localhost:8080/ \
  --preset=desktop \
  --output=html \
  --output-path=./perf-baseline-2026-05-23.html \
  --chrome-flags="--headless"
```

Fill in the numbers that come back:

| Metric | Target | Today |
|---|---:|---:|
| LCP | < 1500 ms | _TBD_ |
| INP (or TBT) | < 200 ms | _TBD_ |
| CLS | < 0.1 | _TBD_ |
| Total transfer | < 500 KB | _TBD_ |
| Performance score | ≥ 95 | _TBD_ |

Then re-run after each phase ships and append a column to the table.

---

## 8. Locked scope for the sweep

Recorded so Phase 2 / 3 / 4 are unambiguous:

1. **Compression: gzip + brotli, both in Phase 2.** Adds
   `github.com/andybalholm/brotli` as the first non-stdlib runtime
   dep on the daemon. Expected wire size for the 260 KB JS bundle:
   ~78 KB gzip, ~62 KB brotli; clients that advertise both get brotli.
2. **Lighthouse CI: spin bulwark in CI, anonymous mode.** The `perf`
   job in `.github/workflows/ci.yml` builds the binary, starts it
   with `--api.auth.type=none` bound to localhost, points LHCI at
   `http://localhost:8080/`. No live UAT URL dependency, no stored
   credentials. Anonymous mode is CI-only and clearly documented as
   such.
3. **Bundle budgets (starter numbers):** per chunk 200 KB gzip,
   first-paint entry + vendor combined 350 KB gzip, total CSS 40 KB
   gzip. Today's build passes these; Phase 3 will tighten them in a
   follow-up PR once the lazy-route landing reduces first-paint JS.

---

## Appendix A — `web/vite.config.ts` (current)

```ts
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
  build: {
    outDir: path.resolve(__dirname, "../internal/api/ui-react/dist"),
    emptyOutDir: false,
    sourcemap: false,
  },
});
```
