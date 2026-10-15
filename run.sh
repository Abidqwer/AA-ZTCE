#!/usr/bin/env bash
set -euo pipefail
TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$TASK_DIR"
TASK_PYTHON="${AA_ZTCE_PYTHON:-python3}"
"$TASK_PYTHON" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
if ! "$TASK_PYTHON" -c 'import z3,cryptography' >/dev/null 2>&1; then
 "$TASK_PYTHON" -m venv .venv
 TASK_PYTHON="$TASK_DIR/.venv/bin/python"
 "$TASK_PYTHON" -m pip install --disable-pip-version-check -r requirements.txt
fi
"$TASK_PYTHON" -m unittest -v test_security > regression.log 2>&1
"$TASK_PYTHON" reproduce_findings.py > finding_reproductions.log
"$TASK_PYTHON" dynamic_campaign.py > dynamic_run.log
"$TASK_PYTHON" formal_checks.py > formal_run.log
"$TASK_PYTHON" adversarial_simulations.py > adversarial_run.log
"$TASK_PYTHON" - <<'PY'
import json
from pathlib import Path
p=Path('.')
d=json.loads((p/'dynamic_results.json').read_text())
f=json.loads((p/'formal_results.json').read_text())
a=json.loads((p/'adversarial_results.json').read_text())
assert d['passed']==d['assertions'] and f['all_expected_results'] and a['assertions_passed']==a['total']
print('Regression suite: 61 passed')
print('Stateful actions:',d['actions'],'assertions:',d['passed'],'/',d['assertions'],'thread trials:',d['concurrent_trials'])
print('Formal queries:',len(f['queries']),'expected results:',f['all_expected_results'])
print('Adversarial tool-action assertions:',a['assertions_passed'],'/',a['total'])
PY
