#!/usr/bin/env bash
# Negative test for the commit-identity check (scripts/commit-identity-check.sh).
#
# This suite exists because the commit-identity gate used to accept any email
# merely ENDING in @users.noreply.github.com: the old pattern
# `^noreply@github\.com$|@users\.noreply\.github\.com$` had a second
# alternative that was unanchored on the left and required no `<numeric-id>+`
# prefix, so `caradon-agent@users.noreply.github.com` (a well-shaped but
# unprovisioned address that resolves to no account) passed, and so would
# `attacker@users.noreply.github.com`.
#
# The class-H specimen below is the negative fixture. If the check ever
# regresses to accepting it, THIS TEST FAILS.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/commit-identity-check.sh"

fail=0

# run_check <email> -> 0 if the check ACCEPTS the email, nonzero otherwise.
run_check() {
  printf 'deadbeef %s %s\n' "$1" "$1" | bash "$check" >/dev/null 2>&1
}

expect_accept() {
  local email="$1"
  if run_check "$email"; then
    echo "PASS (accept) : $email"
  else
    echo "FAIL: expected ACCEPT but check REJECTED: $email" >&2
    fail=1
  fi
}

expect_reject() {
  local email="$1"
  if run_check "$email"; then
    echo "FAIL: expected REJECT but check ACCEPTED: $email  (defect live)" >&2
    fail=1
  else
    echo "PASS (reject) : $email"
  fi
}

# Positive fixtures — provisioned GitHub noreply addresses (numeric id + name).
expect_accept "325855022+caradon-harness@users.noreply.github.com"
expect_accept "43620530+ranklancer@users.noreply.github.com"

# Legacy generic GitHub noreply address (used by GitHub for web-flow merges).
expect_accept "noreply@github.com"

# NEGATIVE fixture — class-H specimen: unregistered @users.noreply.github.com
# address. No numeric-id prefix; resolves to no account. The unfixed pattern
# accepts it; the fixed pattern must reject it.
expect_reject "caradon-agent@users.noreply.github.com"

# NEGATIVE — arbitrary attacker-shaped address, same defect shape.
expect_reject "attacker@users.noreply.github.com"

# NEGATIVE — the id prefix must be a NUMBER, not arbitrary text.
expect_reject "attacker+caradon-harness@users.noreply.github.com"

# NEGATIVE — the username side must not be empty.
expect_reject "325855022+@users.noreply.github.com"

if [ "$fail" -ne 0 ]; then
  echo "commit-identity negative test: FAILED" >&2
  exit 1
fi
echo "commit-identity negative test: OK"
