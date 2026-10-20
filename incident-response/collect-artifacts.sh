#!/usr/bin/env bash
# Collect forensic artifacts for a pod and bundle them with a SHA-256 manifest.
# Usage: collect-artifacts.sh -n <namespace> -p <pod> [-o <output-dir>] [--dry-run]
set -euo pipefail

NS="" POD="" OUT="./evidence/$(date -u +%Y%m%d-%H%M%S)" DRY_RUN=0
usage() { echo "usage: $0 -n <namespace> -p <pod> [-o <output-dir>] [--dry-run]" >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) NS="${2:-}"; shift 2 ;;
    -p) POD="${2:-}"; shift 2 ;;
    -o) OUT="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) usage ;;
  esac
done
[[ -n "$NS" && -n "$POD" ]] || usage

if [[ "$DRY_RUN" -eq 1 ]]; then
  for a in "get pod $POD -n $NS -o json" "get node <node> -o json" "get networkpolicy -n $NS -o yaml" \
           "get rolebinding -n $NS -o yaml" "get pods -n $NS -o wide --show-labels"; do
    echo "[dry-run] kubectl $a"
  done
  echo "[dry-run] tar czf ${OUT}.tar.gz ${OUT}"
  exit 0
fi

umask 077
mkdir -p "$OUT"
kubectl get pod "$POD" -n "$NS" -o json >"$OUT/pod.json"
NODE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.spec.nodeName}')
[[ -n "$NODE" ]] && kubectl get node "$NODE" -o json >"$OUT/node.json"
kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.name}{"\t"}{.image}{"\t"}{.imageID}{"\n"}{end}' >"$OUT/images.tsv"
kubectl get networkpolicy -n "$NS" -o yaml >"$OUT/networkpolicies.yaml"
kubectl get rolebinding -n "$NS" -o yaml >"$OUT/rolebindings.yaml"
kubectl get pods -n "$NS" -o wide --show-labels >"$OUT/namespace-pods.txt"
(cd "$OUT" && sha256sum ./* >SHA256SUMS)
tar czf "${OUT}.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
echo "bundle: ${OUT}.tar.gz sha256=$(sha256sum "${OUT}.tar.gz" | cut -d' ' -f1)"
