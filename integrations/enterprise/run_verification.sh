#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${TASK_ROOT}/published/engine.py" ]]; then python3 "${TASK_ROOT}/prepare_checkout.py"; fi
TASK_PYTHON="${AA_ZTCE_PYTHON:-python3}"
"$TASK_PYTHON" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
if ! "$TASK_PYTHON" -c 'import cryptography,z3' >/dev/null 2>&1; then
  "$TASK_PYTHON" -m venv "$TASK_ROOT/.venv"
  TASK_PYTHON="$TASK_ROOT/.venv/bin/python"
  "$TASK_PYTHON" -m pip install --disable-pip-version-check -r "$TASK_ROOT/published/requirements.txt"
fi
exec "$TASK_PYTHON" "$TASK_ROOT/verify.py" "$@"
