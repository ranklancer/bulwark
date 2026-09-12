#!/usr/bin/env bash
# Commit-identity check: author/committer emails must be GitHub noreply
# addresses.
#
# Input : lines of "<hash> <author-email> <committer-email>" on stdin (the
#         format emitted by `git log --format='%H %ae %ce'`).
# Output: "commit-identity: OK" on stdout when every email passes; otherwise
#         one or more `::error::` lines on stderr and a nonzero exit.
#
# GitHub noreply addresses come in two forms:
#   legacy generic : noreply@github.com
#   modern         : <numeric-id>+<username>@users.noreply.github.com
#
# The modern form MUST carry the numeric-id prefix. An address that merely
# ENDS in @users.noreply.github.com (e.g. caradon-agent@users.noreply.github.com)
# is well-shaped but unprovisioned: it resolves to no account. The old check
# used the pattern `^noreply@github\.com$|@users\.noreply\.github\.com$`, whose
# second alternative was unanchored on the left and required no `<numeric-id>+`
# prefix, so any unregistered or attacker-shaped address passed. This pattern
# anchors both alternatives, requires the numeric id, and validates the
# username side (alphanumeric start/end, hyphens allowed but never doubled).
set -euo pipefail

pattern='^(noreply@github\.com|[0-9]+\+[A-Za-z0-9]([A-Za-z0-9]|-[A-Za-z0-9])*@users\.noreply\.github\.com)$'

bad=0
while read -r h ae ce; do
  [ -z "$h" ] && continue
  short="${h:0:7}"
  if ! printf '%s' "$ae" | grep -qiE "$pattern"; then
    echo "::error::commit ${short}: author email '${ae}' is not a GitHub noreply address" >&2
    bad=1
  fi
  if ! printf '%s' "$ce" | grep -qiE "$pattern"; then
    echo "::error::commit ${short}: committer email '${ce}' is not a GitHub noreply address" >&2
    bad=1
  fi
done
[ "$bad" -eq 0 ] || { echo "::error::commit-identity check FAILED" >&2; exit 1; }
echo "commit-identity: OK"
