#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/apps/security-ui"

BACKEND_PORT="${BACKEND_PORT:-5001}"
FRONTEND_PORT_START="${FRONTEND_PORT_START:-3000}"
BACKEND_REQUIREMENTS_FILE="${BACKEND_REQUIREMENTS_FILE:-requirements_minimal.txt}"
SKIP_FRONTEND_INSTALL="${SKIP_FRONTEND_INSTALL:-0}"
SKIP_BACKEND_INSTALL="${SKIP_BACKEND_INSTALL:-0}"

info() { printf "%s\n" "$*"; }
err() { printf "%s\n" "$*" >&2; }

check_port_listening() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
}

pick_free_port() {
  local port="$1"
  while check_port_listening "$port"; do
    port=$((port + 1))
  done
  printf "%s" "$port"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

health_check() {
  local url="$1"
  if have_cmd curl; then
    curl -fsS "$url" >/dev/null
  else
    python3 - <<'PY'
import sys, urllib.request
urllib.request.urlopen(sys.argv[1]).read()
PY
  fi
}

info "🚀 Starting Break-Glass (local)"
info "================================"

if ! have_cmd python3; then
  err "❌ python3 not found. Install Python 3 first."
  exit 1
fi

if [ ! -d "$BACKEND_DIR" ]; then
  err "❌ Backend folder not found at: $BACKEND_DIR"
  exit 1
fi

if [ ! -d "$FRONTEND_DIR" ]; then
  err "❌ Frontend folder not found at: $FRONTEND_DIR"
  exit 1
fi

info "📡 Backend: ensuring venv + deps"
if check_port_listening "$BACKEND_PORT"; then
  info "✅ Backend already listening on port $BACKEND_PORT"
else
  pushd "$BACKEND_DIR" >/dev/null

  if [ ! -d "venv" ]; then
    info "🔄 Creating backend venv"
    python3 -m venv venv
  fi

  # shellcheck disable=SC1091
  source venv/bin/activate

  if [ "$SKIP_BACKEND_INSTALL" != "1" ]; then
    if [ ! -f "$BACKEND_REQUIREMENTS_FILE" ]; then
      err "❌ Requirements file not found: backend/$BACKEND_REQUIREMENTS_FILE"
      err "   Set BACKEND_REQUIREMENTS_FILE=requirements.txt if needed."
      exit 1
    fi

    info "📦 Installing backend deps from $BACKEND_REQUIREMENTS_FILE"
    python -m pip install --upgrade pip >/dev/null
    pip install -r "$BACKEND_REQUIREMENTS_FILE" >/dev/null
  else
    info "⏭️  Skipping backend dependency install (SKIP_BACKEND_INSTALL=1)"
  fi

  chmod +x start_proper.sh
  info "🏃 Starting backend on http://localhost:$BACKEND_PORT"
  # start_proper.sh uses run.py which binds to 5001 by default.
  ./start_proper.sh &
  BACKEND_PID=$!
  popd >/dev/null
  info "✅ Backend started (PID: $BACKEND_PID)"
fi

info "⏱️  Waiting for backend health..."
attempts=0
until health_check "http://localhost:$BACKEND_PORT/health"; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 30 ]; then
    err "❌ Backend did not become healthy at /health within 30s."
    err "   Check logs above for errors."
    exit 1
  fi
  sleep 1
done
info "✅ Backend health OK"

info "🎨 Frontend: ensuring deps + starting dev server"
FRONTEND_PORT="$(pick_free_port "$FRONTEND_PORT_START")"
pushd "$FRONTEND_DIR" >/dev/null

if [ "$SKIP_FRONTEND_INSTALL" != "1" ]; then
  if [ ! -d "node_modules" ]; then
    if have_cmd pnpm; then
      info "📦 Installing frontend deps (pnpm)"
      pnpm install
    else
      info "📦 Installing frontend deps (npm)"
      npm install
    fi
  else
    info "✅ Frontend deps already present (node_modules)"
  fi
else
  info "⏭️  Skipping frontend dependency install (SKIP_FRONTEND_INSTALL=1)"
fi

info "🏃 Starting frontend on http://localhost:$FRONTEND_PORT"
if have_cmd pnpm; then
  pnpm dev -p "$FRONTEND_PORT" &
else
  npm run dev -- -p "$FRONTEND_PORT" &
fi
FRONTEND_PID=$!
popd >/dev/null
info "✅ Frontend started (PID: $FRONTEND_PID)"

info ""
info "🎉 Break-Glass local stack is up"
info "================================"
info "📍 Backend API:  http://localhost:$BACKEND_PORT"
info "🌐 Frontend UI:  http://localhost:$FRONTEND_PORT"
info "➡️  Go to:        /emergency-access"
info ""
info "Press Ctrl+C to stop (both processes will exit)"

cleanup() {
  info "\n🧹 Stopping services..."
  if [ -n "${FRONTEND_PID:-}" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  if [ -n "${BACKEND_PID:-}" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
}
trap cleanup INT TERM

wait
