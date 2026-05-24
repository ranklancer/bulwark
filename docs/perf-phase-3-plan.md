# Phase 3 — Structural code splitting (perf/code-splitting)

Branch carries five commits, each landed separately so revert / bisect
is clean. All scope is frontend: no Go changes.

| # | Commit subject | Files touched |
|---|---|---|
| 1 | `perf: Phase 3 plan doc` | `docs/perf-phase-3-plan.md` |
| 2 | `perf: bundle visualizer script` | `web/package.json`, `web/package-lock.json`, `web/.gitignore` |
| 3 | `perf: split react + react-router into a vendor chunk` | `web/vite.config.ts` |
| 4 | `perf: lazy-load long-tail routes` | `web/src/App.tsx` |
| 5 | `perf: prefetch the Dashboard chunk from the Login page` | `web/src/pages/Login.tsx` |

## What each commit ships

### 2 — Bundle visualizer
- `vite-bundle-visualizer` devDep.
- `npm run bundle:report` script that emits an interactive treemap to
  a local file (operator-only; treemap output is gitignored).
- Lets the operator + future passes point at "what's actually heavy"
  without re-reading the build log.

### 3 — Vendor chunk
- `manualChunks` in `vite.config.ts` peels `react`, `react-dom`, and
  `react-router-dom` into a `vendor.[hash].js` chunk separate from
  the app's own code.
- App churn (every release) doesn't bust the vendor cache. Operators
  who upgrade frequently benefit on second/third loads of each
  release; first-load size is unchanged.

### 4 — Lazy routes
- Convert eager imports to `React.lazy()` for pages an authenticated
  operator visits second:
  - `Audit`, `Settings`, `Snapshots`, `HistoryDetail`,
    `Containers`, `Notifiers`.
- Keep eager (first-paint + high-frequency surface):
  - `Login`, `Dashboard`, `Queue`, `History`, plus all shell chrome
    (`AppShell`, `RequireAuth`).
- Each lazy route gets a `<Suspense fallback={<Spinner />}>` wrapper
  at the route mount; the existing `components/ui/Spinner` is the
  placeholder.
- `AddNotifierModal` is **not** explicitly lazy-loaded: it's imported
  only from `Notifiers.tsx`, which is lazy, so Vite already
  tree-shakes the modal into the same chunk. An explicit `React.lazy`
  would add a second round trip for negligible benefit.

### 5 — Login-side prefetch
- On `Login` mount, fire `import("../pages/Dashboard")` so the
  post-auth chunk is fetched in parallel with the operator typing
  their token. By the time they hit "Sign in," Dashboard is cached.
- No prefetch on already-authenticated visits (forward-proxy
  deployments bounce past `/login` immediately).

## Expected post-Phase-3 numbers

Rough targets after all five commits land (gzip):

| Chunk | Estimated size |
|---|---:|
| Entry (`Login` + shell + auth context) | 35–55 KB |
| Vendor (react + react-dom + react-router-dom) | ~50 KB |
| Post-login (`Dashboard`) | 5–10 KB |
| `Queue` (eager, in entry) | 3–5 KB |
| `History` (eager, in entry) | 5–8 KB |
| `Audit` (lazy) | 5–10 KB |
| `Settings` (lazy, biggest after the per-tab forms landed) | 15–25 KB |
| `Notifiers` + `AddNotifierModal` (lazy) | 15–25 KB |
| `Snapshots` (lazy) | 5–10 KB |
| `HistoryDetail` (lazy) | 5–10 KB |
| `Containers` (lazy) | 5–10 KB |

Today's single bundle is 260 KB raw / 78 KB gzip; first-paint after
Phase 3 should land around 85–105 KB gzip (entry + vendor), with
long-tail routes loading 5–25 KB each on first visit.

## What this phase deliberately does NOT do

- Switching from useEffect+useState data hooks to TanStack Query —
  out of scope; the existing hooks work and the SWR cache wouldn't
  meaningfully change first-paint metrics.
- Replacing react-router-dom — same boat; the current router is
  small enough and battle-tested.
- Image / font optimisation — bulwark ships neither.
- Server push, brotli pre-encoding, etc. — Phase 2 territory.

## Verification

After all five commits land:

```sh
cd web
npm run build
# Read the chunk table off the build output and confirm:
#   - multiple chunks emitted (not one monolithic bundle)
#   - vendor.[hash].js exists and contains react + router
#   - per-route chunks named after the lazy components
```

Manual smoke (operator with the binary built):

1. Load `/` cold → entry + vendor + Dashboard chunks fetch.
2. Navigate to `/audit` → Audit chunk fetches; nav is instant on
   subsequent visits.
3. View the network tab on a `/login` cold load → Dashboard chunk
   fetches in parallel with HTML parse, before the operator submits.
4. `npm run bundle:report` → treemap opens; vendor is its own box.
