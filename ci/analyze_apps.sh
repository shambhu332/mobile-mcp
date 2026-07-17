#!/bin/bash
# ci/analyze_apps.sh
set -euo pipefail

PYTHON_BIN="${PYTHON:-}"
if [ -z "$PYTHON_BIN" ] && [ -x ".venv/bin/python" ]; then
	PYTHON_BIN=".venv/bin/python"
fi
if [ -z "$PYTHON_BIN" ]; then
	PYTHON_BIN="python3"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

exec "$PYTHON_BIN" "$REPO_ROOT/concolic_engine/auto_analyze.py" "$@"
