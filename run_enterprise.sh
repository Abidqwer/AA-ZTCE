#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${ROOT}/published/engine.py" ]]; then python3 "${ROOT}/prepare_checkout.py"; fi
cd "$ROOT"
bash run_soc.sh test
PYTHON="${AA_ZTCE_PYTHON:-python3}"
if [[ -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; fi
if command -v go >/dev/null; then
  export AA_ZTCE_GO="$(command -v go)"
  go -C terraform-provider-aaztce mod verify
  go -C terraform-provider-aaztce test ./...
  go -C terraform-provider-aaztce build -buildvcs=false -trimpath -o terraform-provider-aaztce
else
  echo 'NOT RUN: Go source build (Go is not installed); bundled binary is Linux/amd64 only.'
fi
if command -v terraform >/dev/null && [[ -x terraform-provider-aaztce/terraform-provider-aaztce ]]; then
  export AA_ZTCE_TERRAFORM="$(command -v terraform)"
fi
"$PYTHON" enterprise_verify.py
if command -v helm >/dev/null; then
  helm lint charts/aaztce --set image.repository=local/aaztce --set credentialsSecret=managed-pilot
  helm template test charts/aaztce --set image.repository=local/aaztce --set credentialsSecret=managed-pilot >/dev/null
else
  echo 'NOT RUN: Helm lint/template (Helm is not installed).'
fi
