#!/usr/bin/env bash
# Installs Bulwark's git pre-commit hook in the local repository. The hook
# re-runs scripts/check-pii.sh on each commit so accidental PII never lands
# in source control.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hook_path="$repo_root/.git/hooks/pre-commit"

cat > "$hook_path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
exec "$repo_root/scripts/check-pii.sh"
EOF
chmod +x "$hook_path"
echo "installed pre-commit hook at $hook_path"
