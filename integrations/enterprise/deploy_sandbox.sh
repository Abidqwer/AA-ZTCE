#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${AA_ZTCE_IMAGE:?Set AA_ZTCE_IMAGE to a writable registry repository, without a tag}"
: "${AA_ZTCE_SECRET:?Set AA_ZTCE_SECRET to an existing managed TLS/config Kubernetes Secret}"
AA_ZTCE_NAMESPACE="${AA_ZTCE_NAMESPACE:-default}"
if [[ ! -f "$ROOT/published/engine.py" ]]; then python3 "$ROOT/prepare_checkout.py"; fi
for command in docker helm kubectl; do command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }; done
kubectl -n "$AA_ZTCE_NAMESPACE" get secret "$AA_ZTCE_SECRET" >/dev/null
docker build -t "$AA_ZTCE_IMAGE:0.4.0" "$ROOT"
docker push "$AA_ZTCE_IMAGE:0.4.0"
helm upgrade --install aaztce "$ROOT/charts/aaztce" --namespace "$AA_ZTCE_NAMESPACE" \
  --set-string "image.repository=$AA_ZTCE_IMAGE" --set-string "credentialsSecret=$AA_ZTCE_SECRET" --wait --timeout 180s
