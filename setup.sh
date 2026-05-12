#!/bin/sh
# Setup script — adds npm supply chain audit to a repo's pre-push hook.
# Usage: ./setup.sh [target-repo-dir]
#
# This script is idempotent — safe to run multiple times.

set -euo pipefail

TARGET_DIR="${1:-.}"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
HOOKS_DIR="$TARGET_DIR/.git/hooks"

if [ ! -d "$TARGET_DIR/.git" ]; then
  echo "error: $TARGET_DIR is not a git repository"
  exit 1
fi

# ── Pre-push hook ────────────────────────────────────────────
HOOK_FILE="$HOOKS_DIR/pre-push"
MARKER="# npm-supply-chain-audit"

HOOK_SNIPPET="
$MARKER
echo \"🔍 Running npm supply chain audit...\"
REPO_ROOT=\"\$(git rev-parse --show-toplevel)\"
if command -v npx >/dev/null 2>&1; then
  npx --yes npm-supply-chain-audit --dir \"\$REPO_ROOT\" --ci
else
  AUDIT_SCRIPT=\"\$REPO_ROOT/npm-supply-chain-audit/scripts/audit.mjs\"
  if [ -f \"\$AUDIT_SCRIPT\" ]; then
    node \"\$AUDIT_SCRIPT\" --dir \"\$REPO_ROOT\" --ci
  else
    echo \"⚠️  npm-supply-chain-audit not found, skipping\"
    exit 0
  fi
fi
if [ \$? -ne 0 ]; then
  echo \"\"
  echo \"❌ Compromised npm packages detected. Push blocked.\"
  echo \"   (use --no-verify to override if absolutely necessary)\"
  exit 1
fi
echo \"✅ npm supply chain audit passed\"
$MARKER-end"

if [ -f "$HOOK_FILE" ] && grep -q "$MARKER" "$HOOK_FILE"; then
  echo "pre-push hook already contains supply chain audit — skipping"
else
  if [ ! -f "$HOOK_FILE" ]; then
    echo "#!/bin/sh" > "$HOOK_FILE"
    chmod +x "$HOOK_FILE"
  fi
  echo "$HOOK_SNIPPET" >> "$HOOK_FILE"
  echo "✅ Added supply chain audit to $HOOK_FILE"
fi

echo ""
echo "Done. The audit will run automatically before each push."
echo "To run manually:  npx npm-supply-chain-audit --dir $TARGET_DIR"
