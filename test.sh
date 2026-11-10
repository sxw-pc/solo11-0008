#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  PYTHON_BIN="python"
fi
exec "$PYTHON_BIN" -m pytest tests -q \
  --cov=gateway \
  --cov-report=term-missing \
  --cov-report=html:htmlcov \
  --cov-fail-under=85
