#!/usr/bin/env bash
#
# Package SiteCheck Monitor into an uploadable plugin zip.
#
# Produces dist/bsc-sitecheck-monitor-<version>.zip with the correct
# folder structure for WordPress's Plugins -> Add New -> Upload Plugin
# screen (which replaces the installed copy when the version is newer).
#
# Gate: only files in the FILES allowlist are packaged. Dev cruft,
# local config, and secrets can never leak into the zip even if they
# later land in the repo.

set -euo pipefail

SLUG="bsc-sitecheck-monitor"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Explicit allowlist of files that may ship.
FILES=(
	"bsc-sitecheck-monitor.php"
	"README.md"
)

# Derive the version from the plugin header so the zip name always
# matches the release being built.
VERSION="$(grep -E '^[[:space:]]*\*[[:space:]]*Version:' "$SLUG.php" | head -1 | sed -E 's/.*Version:[[:space:]]*//' | tr -d '[:space:]')"
if [[ -z "$VERSION" ]]; then
	echo "error: could not read Version from $SLUG.php header" >&2
	exit 1
fi

DIST="$ROOT/dist"
STAGE="$DIST/$SLUG"
rm -rf "$STAGE"
mkdir -p "$STAGE"

for f in "${FILES[@]}"; do
	if [[ ! -f "$f" ]]; then
		echo "error: required file missing: $f" >&2
		exit 1
	fi
	cp "$f" "$STAGE/"
done

ZIP="$DIST/$SLUG-$VERSION.zip"
rm -f "$ZIP"
( cd "$DIST" && zip -rq "$SLUG-$VERSION.zip" "$SLUG" -x '*.DS_Store' )
rm -rf "$STAGE"

echo "Built $ZIP"
unzip -l "$ZIP"
