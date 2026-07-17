#!/usr/bin/env bash
# Risk-tiered, per-package coverage gate (blocking).
#
# Rationale (see docs/the design notes-testing-quality-tiers.md): a single global floor
# lets a security package regress as long as boilerplate elsewhere props up the
# average, and it invites hollow "line-filling" tests on struct/wiring code that
# add a number but no assurance. Instead we hold each package to a floor sized to
# its RISK, exclude genuine boilerplate from the metric entirely, and RATCHET:
# a floor never decreases, and under-target security packages are raised as real
# behavioural (fail-closed) tests land.
#
# Statement-weighted per-package coverage is computed directly from the coverage
# profile (not an unweighted average of per-function percentages).
#
# Usage: scripts/coverage-floors.sh [profile] [total_min]
set -uo pipefail

PROFILE="${1:-/tmp/bulwark.cov}"
TOTAL_MIN="${2:-74.0}"
MODULE="github.com/ranklancer/bulwark/"

# Packages EXCLUDED from the coverage metric (neither floored nor counted in the
# total). Genuine boilerplate where line coverage measures nothing useful:
#   pkg/types              pure data types / enum (String/JSON) plumbing
#   cmd/bulwark            main() + flag/exit wiring (exercised by smoke, not units)
#   cmd/bulwark-diun-relay main() + HTTP-server bootstrap wiring
#   internal/api/ui        HTML dashboard render wiring, no own tests (exercised
#                          only indirectly via internal/api integration tests)
EXCLUDE="pkg/types cmd/bulwark cmd/bulwark-diun-relay internal/api/ui"

# Per-package interim floors. TARGETS (enforced end-state, see the design notes):
#   security/logic tier -> 85 : internal/verify,admit,registry,cve,reconcile,capture,updater
#   base tier           -> 74 : internal/config,configstore,notifier
# Values below the target are the current ratchet baseline; B2/B3 raise both the
# tests and these floors toward the target. DEFAULT applies to everything else.
DEFAULT_FLOOR="74"
declare -A FLOOR=(
  [internal/verify]="78"        # target 85 (ratcheting)
  [internal/admit]="85"         # at target
  [internal/registry]="76"      # target 85 (ratcheting)
  [internal/cve]="81"           # target 85 (ratcheting)
  [internal/reconcile]="85"     # at target
  [internal/capture]="82"       # target 85 (ratcheting)
  [internal/updater]="81"       # target 85 (ratcheting)
  [internal/config]="71"        # target 74 (ratcheting)
  [internal/configstore]="73"   # target 74 (ratcheting)
  [internal/notifier]="71"      # target 74 (ratcheting)
)

if [ ! -s "$PROFILE" ]; then
  echo "coverage-floors: profile not found or empty: $PROFILE" >&2
  exit 2
fi

# Emit "pkg pct" per package plus a final "__TOTAL__ pct", statement-weighted,
# skipping excluded packages.
mapfile -t ROWS < <(awk -v mod="$MODULE" -v excl="$EXCLUDE" '
  BEGIN { n = split(excl, ex, " "); for (i=1;i<=n;i++) exset[ex[i]]=1 }
  NR==1 && $0 ~ /^mode:/ { next }
  {
    # field 1: path:block  field 2: numstmts  field 3: count
    p = $1; sub(/:.*/, "", p); sub(mod, "", p)   # strip module prefix
    sub(/\/[^\/]*\.go$/, "", p)                   # strip /file.go -> package dir
    stmts = $2 + 0; cnt = $3 + 0
    if (p in exset) next
    tot_s[p] += stmts
    if (cnt > 0) tot_c[p] += stmts
    all_s += stmts
    if (cnt > 0) all_c += stmts
  }
  END {
    for (p in tot_s) {
      pct = (tot_s[p] > 0) ? (100.0 * tot_c[p] / tot_s[p]) : 0.0
      printf "%s %.1f\n", p, pct
    }
    tp = (all_s > 0) ? (100.0 * all_c / all_s) : 0.0
    printf "__TOTAL__ %.1f\n", tp
  }
' "$PROFILE")

fail=0
total_pct="$(printf '%s\n' "${ROWS[@]}" | awk '/^__TOTAL__ /{print $2}')"
printf "%-32s %8s %8s   %s\n" "PACKAGE" "COV%" "FLOOR" "STATUS"
printf "%-32s %8s %8s   %s\n" "-------" "----" "-----" "------"
while read -r pkg pct; do
  [ -z "$pkg" ] && continue
  floor="${FLOOR[$pkg]:-$DEFAULT_FLOOR}"
  status="ok"
  if awk -v t="$pct" -v m="$floor" 'BEGIN{exit (t+0 < m+0)?0:1}'; then
    status="BELOW FLOOR"; fail=1
  fi
  printf "%-32s %8s %8s   %s\n" "$pkg" "$pct" "$floor" "$status"
done < <(printf '%s\n' "${ROWS[@]}" | grep -v '^__TOTAL__ ' | sort)

echo "---"
echo "excluded from metric: $EXCLUDE"
printf "TOTAL (excl. boilerplate): %s%%  (floor %s%%)\n" "$total_pct" "$TOTAL_MIN"
if awk -v t="$total_pct" -v m="$TOTAL_MIN" 'BEGIN{exit (t+0 < m+0)?0:1}'; then
  echo "coverage-floors: TOTAL $total_pct% is below floor $TOTAL_MIN%" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "coverage-floors: FAIL — one or more packages under their risk-tiered floor" >&2
  exit 1
fi
echo "coverage-floors: OK"
