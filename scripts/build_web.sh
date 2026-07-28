#!/usr/bin/env bash
# Build the Case Studio frontend and serve it (SPA + API) from FastAPI on :8000.
#
# Usage: bash scripts/build_web.sh
#
# Requires: node/npm (frontend build) and the Python env (uvicorn).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
WEB_DIR="$ROOT/src/secopent/interfaces/web"

echo "==> Building frontend (vite)..."
(cd "$WEB_DIR" && npm run build)

echo "==> Serving SPA + API at http://localhost:8000 (SECOPTENT_WEB_DIST=$WEB_DIR/dist)"
export SECOPTENT_WEB_DIST="$WEB_DIR/dist"
cd "$ROOT"
exec py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000
