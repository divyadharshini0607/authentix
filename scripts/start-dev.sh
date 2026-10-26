#!/usr/bin/env bash
# AUTHENTIX / EduVerify-AI (SIH26261) — Linux / macOS Development Startup Script
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

APP_PORT="${PORT:-3000}"
OCR_PORT="${OCR_SERVICE_PORT:-8001}"
export PORT="$APP_PORT"
export OCR_SERVICE_PORT="$OCR_PORT"
export OCR_SERVICE_URL="${OCR_SERVICE_URL:-http://127.0.0.1:${OCR_PORT}}"

echo "====================================================================="
echo " AUTHENTIX / EduVerify-AI (SIH26261) — Local Startup & Health Check"
echo "====================================================================="

if ! command -v node >/dev/null 2>&1; then
  echo "[ERROR] Node.js is not installed. Please install Node.js >= 22.5.0."
  exit 1
fi

NODE_VER="$(node -p "process.versions.node")"
NODE_MAJOR="$(echo "$NODE_VER" | cut -d. -f1)"
NODE_MINOR="$(echo "$NODE_VER" | cut -d. -f2)"
if [ "$NODE_MAJOR" -lt 22 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 5 ]; }; then
  echo "[ERROR] Detected Node.js v${NODE_VER}. Node.js >= 22.5.0 is required for node:sqlite."
  exit 1
fi
echo "[OK] Node.js v${NODE_VER}"

PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PY_BIN="python"
fi

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo "[OK] Created .env from .env.example"
fi

if [ ! -d "node_modules" ]; then
  echo "[INFO] Installing npm packages..."
  npm install
fi

echo "[INFO] Running database migrations and rule/seed check..."
npm run db:migrate
npm run db:seed

mkdir -p logs
OCR_PID=""

cleanup() {
  if [ -n "$OCR_PID" ] && kill -0 "$OCR_PID" >/dev/null 2>&1; then
    echo "[INFO] Stopping Python OCR service (PID ${OCR_PID})..."
    kill "$OCR_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

if [ -n "$PY_BIN" ]; then
  echo "[INFO] Starting Python OCR & Forensics service on http://127.0.0.1:${OCR_PORT} ..."
  "$PY_BIN" services/ocr_service/server.py > logs/ocr-service.log 2>&1 &
  OCR_PID=$!

  READY=0
  for _ in $(seq 1 25); do
    if curl -fsS "http://127.0.0.1:${OCR_PORT}/health" >/dev/null 2>&1; then
      READY=1
      break
    fi
    sleep 0.4
  done

  if [ "$READY" -ne 1 ]; then
    echo "[ERROR] Python OCR service failed to become healthy on port ${OCR_PORT}."
    cat logs/ocr-service.log || true
    exit 1
  fi
  echo "[OK] Python OCR service healthy at http://127.0.0.1:${OCR_PORT}/health"
else
  echo "[WARN] Python 3 not found; Node fallback extractor will handle PDFs and report raster OCR unavailability."
fi

echo "[INFO] Starting AUTHENTIX server on http://localhost:${APP_PORT} ..."
npm run dev
