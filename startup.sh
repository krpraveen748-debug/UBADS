#!/usr/bin/env bash
set -euo pipefail

port="${PORT:-${API_PORT:-8000}}"
exec python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port "$port" --no-access-log
