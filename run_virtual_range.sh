#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ ! -f "$ROOT/published/engine.py" ]]; then python3 "$ROOT/prepare_checkout.py"; fi
CACHE="${AA_RANGE_CACHE:-$ROOT/.assurance_cache}"
BASE_PYTHON="${AA_ZTCE_PYTHON:-python3}"
if ! "$BASE_PYTHON" -c 'import cryptography,z3,pkcs11' >/dev/null 2>&1; then
  "$BASE_PYTHON" -m venv "$ROOT/.range_venv"
  BASE_PYTHON="$ROOT/.range_venv/bin/python"
  "$BASE_PYTHON" -m pip install --disable-pip-version-check -r "$ROOT/assurance/requirements.txt"
fi
NO_MODEL=()
for arg in "$@"; do if [[ "$arg" == "--endpoint" ]]; then NO_MODEL=(--no-model); fi; done
"$BASE_PYTHON" "$ROOT/range/bootstrap.py" --cache "$CACHE" "${NO_MODEL[@]}"
# The generated file contains executable/library paths only, never credentials.
eval "$("$BASE_PYTHON" - "$CACHE/environment.json" <<'PY'
import json,shlex,sys
for key,value in json.load(open(sys.argv[1])).items():print('export '+key+'='+shlex.quote(value))
PY
)"
export AA_ZTCE_PYTHON="$BASE_PYTHON"
bash "$ROOT/run_enterprise.sh"
mkdir -p "$ROOT/results/assurance"
"$BASE_PYTHON" -u "$ROOT/assurance_verify.py" > "$ROOT/results/assurance/protocol_checks.log" 2>&1 || { cat "$ROOT/results/assurance/protocol_checks.log"; exit 1; }
cat "$ROOT/results/assurance/verification.json"
MODEL_ARGS=()
if [[ ${#NO_MODEL[@]} -eq 0 ]]; then MODEL_ARGS=(--llama-server "$AA_RANGE_LLAMA" --model-file "$AA_RANGE_MODEL"); fi
exec "$BASE_PYTHON" -u "$ROOT/virtual_range.py" "${MODEL_ARGS[@]}" "$@"
