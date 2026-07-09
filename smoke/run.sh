#!/usr/bin/env bash
# Bulwark smoke suite — builds the real bulwark binary and exercises the digest pinning
# capture / pin / canary surface END-TO-END against hermetic fixtures. No
# network and no Docker: registry resolution is supplied via --digest, so the
# suite runs anywhere (dev box + CI). Run via `make smoke`.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
BIN="$WORK/bulwark"
DIGEST="sha256:$(printf 'a%.0s' {1..64})"
PASS=0; FAIL=0
trap 'rm -rf "$WORK"' EXIT

ok()  { PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
has() { grep -q -- "$2" "$1"; }

echo "== build bulwark =="
( cd "$ROOT" && go build -o "$BIN" ./cmd/bulwark ) || { echo "BUILD FAILED"; exit 1; }

# ------------------------------------------------------------------ scenario 1
echo "== 1. discovery + classification matrix (dry-run, no network) =="
S1="$WORK/s1"; mkdir -p "$S1/flat/apiSvc" "$S1/single"
printf 'TAG=9.9\n' > "$S1/flat/apiSvc/.env"
cat > "$S1/flat/apiSvc/compose.yaml" <<'Y'
services:
  api:
    image: ghcr.io/acme/api:1.4
  web:
    image: nginx:latest
  builder:
    build: .
    image: local/thing:2
  varsvc:
    image: ghcr.io/acme/svc:${TAG}
Y
printf 'services:\n  solo:\n    image: caddy:2.8\n' > "$S1/single/compose.yaml"
O1="$WORK/o1.txt"
"$BIN" capture --stacks-path "$S1/flat,$S1/single" --digest "$DIGEST" > "$O1" 2>&1
has "$O1" "apiSvc" && has "$O1" "single" && ok "discovers flat-Dockge dir + single-file stack" || { bad "discovery"; cat "$O1"; }
has "$O1" "api (line" && has "$O1" "ghcr.io/acme/api:1.4@$DIGEST" && ok "pins a public tagged image (index digest)" || bad "pinnable classification"
has "$O1" "web: skip" && ok ":latest deferred (skip)" || bad ":latest not skipped"
has "$O1" "builder: skip" && ok "build-context deferred (skip)" || bad "build not skipped"
has "$O1" "varsvc: skip" && ok "\${VAR} image deferred (skip)" || bad "\${VAR} not skipped"

# ------------------------------------------------------------------ scenario 2
echo "== 2. managed-backend rejection (validate-config) =="
CFG="$WORK/managed.yaml"
cat > "$CFG" <<'Y'
classification:
  default_risk: review
sources:
  - name: portainer-prod
    type: portainer
    endpoint: http://example.invalid
Y
if "$BIN" validate-config --config "$CFG" > "$WORK/o2.txt" 2>&1; then bad "managed backend was NOT rejected"; else ok "managed (portainer) source rejected by validate-config"; fi

# ------------------------------------------------------------------ scenario 3
echo "== 3. apply: write + backup + idempotent + rollback (throwaway copy) =="
S3="$WORK/s3"; D3="$WORK/data3"; mkdir -p "$S3/app"
printf 'services:\n  app:\n    image: myapp:2.1   # do not touch this comment\n    restart: unless-stopped\n' > "$S3/app/compose.yaml"
ORIG="$(cat "$S3/app/compose.yaml")"
"$BIN" capture --stacks-path "$S3" --data-dir "$D3" --digest "$DIGEST" --apply > "$WORK/o3.txt" 2>&1
has "$S3/app/compose.yaml" "myapp:2.1@$DIGEST" && ok "pin written in place" || { bad "pin not written"; cat "$S3/app/compose.yaml"; }
has "$S3/app/compose.yaml" "# do not touch this comment" && ok "trailing comment preserved" || bad "comment lost"
ls "$D3"/pin-backups/app/*-compose.yaml >/dev/null 2>&1 && ok "backup created" || bad "no backup"
O3B="$("$BIN" capture --stacks-path "$S3" --data-dir "$D3" --digest "$DIGEST" --apply 2>&1)"
echo "$O3B" | grep -q "already pinned (no-op)" && ok "idempotent re-run is a no-op" || { bad "not idempotent"; echo "$O3B"; }
"$BIN" pin rollback --data-dir "$D3" app/app > "$WORK/o3r.txt" 2>&1
[ "$(cat "$S3/app/compose.yaml")" = "$ORIG" ] && ok "pin rollback restores byte-for-byte" || bad "rollback not byte-identical"

# ------------------------------------------------------------------ scenario 4
echo "== 4. canary lifecycle (start -> status -> promote -> rollback) =="
S4="$WORK/s4"; D4="$WORK/data4"; mkdir -p "$S4/db"
printf 'services:\n  db:\n    image: postgres:16\n' > "$S4/db/compose.yaml"
DBORIG="$(cat "$S4/db/compose.yaml")"
"$BIN" capture --stacks-path "$S4" --data-dir "$D4" --digest "$DIGEST" --apply >/dev/null 2>&1
"$BIN" canary start --data-dir "$D4" db/db >/dev/null 2>&1 && ok "canary start (candidate -> canary)" || bad "canary start"
"$BIN" canary status --data-dir "$D4" 2>/dev/null | grep -q "canary" && ok "status shows canary" || bad "status canary"
"$BIN" canary promote --data-dir "$D4" db/db >/dev/null 2>&1 && ok "canary promote" || bad "canary promote"
"$BIN" canary status --data-dir "$D4" 2>/dev/null | grep -q "promoted" && ok "status shows promoted" || bad "status promoted"
"$BIN" canary rollback --data-dir "$D4" db/db >/dev/null 2>&1
[ "$(cat "$S4/db/compose.yaml")" = "$DBORIG" ] && ok "canary rollback restores compose" || bad "canary rollback"

# ------------------------------------------------------------------ scenario 5
echo "== 5. verify-gate wiring (verify disabled => allow) =="
VCFG="$WORK/verify.yaml"
cat > "$VCFG" <<'Y'
classification:
  default_risk: review
verify:
  enabled: false
Y
S5="$WORK/s5"; mkdir -p "$S5/svc"
printf 'services:\n  svc:\n    image: ghcr.io/acme/app:3.0\n' > "$S5/svc/compose.yaml"
"$BIN" capture --stacks-path "$S5" --digest "$DIGEST" --verify --config "$VCFG" > "$WORK/o5.txt" 2>&1
has "$WORK/o5.txt" "verify: allow" && ok "capture --verify reports a gate verdict (allow when verify disabled)" || { bad "verify wiring"; cat "$WORK/o5.txt"; }

echo
echo "== smoke summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
