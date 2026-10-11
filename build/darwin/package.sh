#!/usr/bin/env bash
set -euo pipefail

# Usage: package.sh <binary_path> <version> [output_app_dir] [build_number] [output_zip]
BIN_PATH="${1:-work/gostpx}"
VERSION="${2:-v0.2.0-alpha.1}"
APP_DEST="${3:-work/gostpx.app}"
BUILD_NUM="${4:-${GITHUB_RUN_NUMBER:-1}}"
ZIP_DEST="${5:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ ! -f "$BIN_PATH" ]; then
  echo "Error: binary not found at $BIN_PATH" >&2
  exit 1
fi

rm -rf "$APP_DEST"
mkdir -p "$APP_DEST/Contents/MacOS"
cp "$BIN_PATH" "$APP_DEST/Contents/MacOS/gostpx"
chmod +x "$APP_DEST/Contents/MacOS/gostpx"

# CFBundleShortVersionString must be numeric: v0.2.0-alpha.1 -> 0.2.0
SHORT_VER="${VERSION#v}"
SHORT_VER="${SHORT_VER%%-*}"

sed -e "s/__SHORT_VERSION__/$SHORT_VER/" -e "s/__BUILD__/$BUILD_NUM/" \
  "$SCRIPT_DIR/Info.plist" > "$APP_DEST/Contents/Info.plist"

plutil -lint "$APP_DEST/Contents/Info.plist"

# Remove extended attributes (resource fork/detritus) before signing
xattr -cr "$APP_DEST" 2>/dev/null || true
xattr -c "$APP_DEST" 2>/dev/null || true
xattr -dr com.apple.FinderInfo "$APP_DEST" 2>/dev/null || true
xattr -d com.apple.FinderInfo "$APP_DEST" 2>/dev/null || true
dot_clean "$APP_DEST" 2>/dev/null || true

# Ad-hoc signature: no Developer ID (ADR-005), but required for macOS execution
codesign --force --deep --sign - "$APP_DEST"
codesign --verify --verbose "$APP_DEST"

echo "Successfully assembled $APP_DEST"

if [ -n "$ZIP_DEST" ]; then
  mkdir -p "$(dirname "$ZIP_DEST")"
  ditto -c -k --keepParent "$APP_DEST" "$ZIP_DEST"
  echo "Created archive $ZIP_DEST"
fi
