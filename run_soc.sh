#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${TASK_ROOT}/published/engine.py" ]]; then python3 "${TASK_ROOT}/prepare_checkout.py"; fi
TASK_PYTHON="${AA_ZTCE_PYTHON:-python3}"
if ! "$TASK_PYTHON" -c 'import cryptography,z3' >/dev/null 2>&1; then
  "$TASK_PYTHON" -m venv "$TASK_ROOT/.venv"
  TASK_PYTHON="$TASK_ROOT/.venv/bin/python"
  "$TASK_PYTHON" -m pip install --disable-pip-version-check -r "$TASK_ROOT/published/requirements.txt"
fi
cd "$TASK_ROOT"
if [[ "${1:-test}" == "test" ]]; then
  "$TASK_PYTHON" verify.py
  "$TASK_PYTHON" soc_verify.py
  "$TASK_PYTHON" measure_false_positives.py
  "$TASK_PYTHON" build_soc_assets.py
  exit 0
fi
if [[ "$1" == "serve" ]]; then
  shift
  exec "$TASK_PYTHON" soc_runtime.py "$@"
fi
exec "$TASK_PYTHON" soc_cli.py "$@"
