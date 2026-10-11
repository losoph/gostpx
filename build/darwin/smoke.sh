#!/usr/bin/env bash
set -euo pipefail

APP_PATH="${1:-}"
if [ -z "$APP_PATH" ]; then
  echo "Usage: $0 <path/to/gostpx.app>" >&2
  exit 1
fi

BIN_PATH="$APP_PATH"
if [ -d "$APP_PATH/Contents/MacOS" ]; then
  BIN_PATH="$APP_PATH/Contents/MacOS/gostpx"
fi

if [ ! -f "$BIN_PATH" ]; then
  echo "Error: binary not found at $BIN_PATH" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d -t gostpx-smoke-XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

export GOSTPX_SELFTEST=1
export GOSTPX_CONFIG_DIR="$TMP_DIR"
export GOSTPX_SYSPROXY_DRY="$TMP_DIR/sysproxy.json"
export GOSTPX_LAUNCH_AGENTS_DIR="$TMP_DIR/LaunchAgents"

echo "=== Running smoke test on $BIN_PATH ==="
echo "GOSTPX_CONFIG_DIR=$GOSTPX_CONFIG_DIR"
echo "GOSTPX_SYSPROXY_DRY=$GOSTPX_SYSPROXY_DRY"
echo "GOSTPX_LAUNCH_AGENTS_DIR=$GOSTPX_LAUNCH_AGENTS_DIR"

set +e
"$BIN_PATH"
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 0 ]; then
  echo "=== Smoke test PASSED (exit code 0) ==="
else
  echo "=== Smoke test FAILED (exit code $EXIT_CODE) ==="
fi

exit $EXIT_CODE
