#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Install dependencies if node_modules is missing or package.json is newer
if [ ! -d "$SCRIPT_DIR/node_modules" ] || [ "$SCRIPT_DIR/package.json" -nt "$SCRIPT_DIR/node_modules" ]; then
  echo "[appsec-context] Installing dependencies…" >&2
  npm install --prefix "$SCRIPT_DIR" --silent
fi

exec node "$SCRIPT_DIR/index.js"
