#!/usr/bin/env bash
# PII scanner. Fails (exit 1) when the working tree contains:
#   * IPv4 addresses that are not in an RFC-reserved range, OR
#   * email addresses that are not on a documentation domain.
#
# RFC-reserved ranges accepted as non-PII:
#   0.0.0.0, 127.0.0.0/8 (loopback), 255.255.255.255 (broadcast),
#   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918 private),
#   192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737 documentation),
#   169.254.0.0/16 (RFC 3927 link-local),
#   224.0.0.0/4, 240.0.0.0/4 (multicast / future use).
#
# Runs as a CI step and as a pre-commit hook (see scripts/install-hooks.sh).
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# Files to skip entirely.
skip_pathspecs=(
    ':!scripts/check-pii.sh'
    ':!go.sum'
    ':!*.png'
    ':!*.jpg'
    ':!*.jpeg'
    ':!*.gif'
    ':!*.ico'
)

failed=0

# --- IPv4 scan -----------------------------------------------------------------
# We use a loose regex (digits-and-dots) and validate octet ranges in awk to
# avoid relying on bounded repetitions, which are buggy in some awk
# implementations (notably mawk).

ipv4_findings=$(git grep -InE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' -- "${skip_pathspecs[@]}" 2>/dev/null || true)

if [[ -n "$ipv4_findings" ]]; then
    bad=$(printf '%s\n' "$ipv4_findings" | awk '
    function is_allowed(ip) {
        n = split(ip, p, ".");
        if (n != 4) return 1;
        for (i = 1; i <= 4; i++) {
            if (p[i] !~ /^[0-9]+$/ || p[i] + 0 > 255) return 1;
        }
        if (ip == "0.0.0.0" || ip == "255.255.255.255") return 1;
        if (p[1] == 127) return 1;
        if (p[1] == 10) return 1;
        if (p[1] == 192 && p[2] == 168) return 1;
        if (p[1] == 192 && p[2] == 0 && p[3] == 2) return 1;
        if (p[1] == 198 && p[2] == 51 && p[3] == 100) return 1;
        if (p[1] == 203 && p[2] == 0 && p[3] == 113) return 1;
        if (p[1] == 172 && p[2] >= 16 && p[2] <= 31) return 1;
        if (p[1] == 169 && p[2] == 254) return 1; # RFC 3927 link-local
        if (p[1] >= 224 && p[1] <= 255) return 1;
        return 0;
    }
    {
        line = $0;
        while (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
            ip = substr(line, RSTART, RLENGTH);
            line = substr(line, RSTART + RLENGTH);
            if (is_allowed(ip)) continue;
            print $0;
            break;
        }
    }')
    if [[ -n "$bad" ]]; then
        echo "PII: IPv4 addresses outside RFC-reserved ranges found:" >&2
        printf '  %s\n' "$bad" >&2
        failed=1
    fi
fi

# --- Email scan ----------------------------------------------------------------

email_findings=$(git grep -InE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+' -- "${skip_pathspecs[@]}" 2>/dev/null || true)

if [[ -n "$email_findings" ]]; then
    bad=$(printf '%s\n' "$email_findings" | awk '
    function email_allowed(addr) {
        if (addr ~ /@example\.(com|org|net)$/) return 1;
        if (addr ~ /^noreply@/) return 1;
        return 0;
    }
    {
        line = $0;
        while (match(line, /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+/)) {
            addr = substr(line, RSTART, RLENGTH);
            line = substr(line, RSTART + RLENGTH);
            if (email_allowed(addr)) continue;
            print $0;
            break;
        }
    }')
    if [[ -n "$bad" ]]; then
        echo "PII: email addresses outside documentation domains found:" >&2
        printf '  %s\n' "$bad" >&2
        failed=1
    fi
fi

if [[ $failed -ne 0 ]]; then
    echo >&2
    echo "Use RFC-reserved address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)" >&2
    echo "and example.com/example.org/example.net domains in code, configs, tests, and docs." >&2
    exit 1
fi

echo "PII scan: clean."
