#!/usr/bin/env bash
# scripts/update-version.sh
# Usage:
#   ./scripts/update-version.sh              # Reads version directly from version.json
#   ./scripts/update-version.sh v0.2.5       # Updates version.json and syncs across all files
#   ./scripts/update-version.sh 0.2.5        # Supports semver without 'v' prefix

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/version.json"

# If a version argument was provided, update version.json first
if [ -n "${1:-}" ]; then
  RAW_VERSION="$1"

  # Ensure format has leading 'v'
  if [[ ! "$RAW_VERSION" =~ ^v ]]; then
    NEW_VERSION="v${RAW_VERSION}"
  else
    NEW_VERSION="${RAW_VERSION}"
  fi

  # Validate semver pattern (e.g. v1.2.3, v1.2.3-beta.1)
  if [[ ! "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
    echo "Expected format: vMAJOR.MINOR.PATCH (e.g. v0.2.5)"
    exit 1
  fi

  # Write back to version.json
  cat <<EOF > "$VERSION_FILE"
{
  "version": "${NEW_VERSION}"
}
EOF
fi

# Ensure version.json exists
if [ ! -f "$VERSION_FILE" ]; then
  echo "❌ Error: ${VERSION_FILE} not found and no version argument provided."
  echo "Usage: $0 [version]"
  exit 1
fi

# Extract version from version.json (compatible with grep/sed without requiring jq)
TARGET_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$VERSION_FILE" | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$TARGET_VERSION" ]; then
  echo "❌ Error: Could not read 'version' key from ${VERSION_FILE}."
  exit 1
fi

echo "🔄 Synchronizing RouteWarden version: ${TARGET_VERSION} (from version.json)"

# Update README.md xcaddy directives if versioned
if [ -f "${ROOT_DIR}/README.md" ]; then
  sed -i '' -E "s|(github\.com/routewarden/caddy-warden)@v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1@${TARGET_VERSION}|g" "${ROOT_DIR}/README.md"
  echo "  ✓ Synchronized README.md"
fi

echo ""
echo "✨ Successfully synchronized version ${TARGET_VERSION}!"
echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: release ${TARGET_VERSION}'"
echo "   git tag ${TARGET_VERSION}"
echo "   git push origin main --tags"
