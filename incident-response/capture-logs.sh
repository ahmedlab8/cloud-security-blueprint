#!/usr/bin/env bash
# Capture container logs, previous logs, describe output and events for a pod.
# Usage: capture-logs.sh -n <namespace> -p <pod> [-o <output-dir>] [--dry-run]
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

capture() { # capture <file> <kubectl args...>
  local file="$1"; shift
  if [[ "$DRY_RUN" -eq 1 ]]; then echo "[dry-run] kubectl $* > ${OUT}/${file}"; return 0; fi
  kubectl "$@" >"${OUT}/${file}" 2>&1 || echo "(command failed: kubectl $*)" >>"${OUT}/${file}"
}

if [[ "$DRY_RUN" -eq 0 ]]; then
  umask 077
  mkdir -p "$OUT"
fi
capture logs-current.txt logs "$POD" -n "$NS" --all-containers --timestamps --prefix
capture logs-previous.txt logs "$POD" -n "$NS" --all-containers --timestamps --prefix --previous
capture describe-pod.txt describe pod "$POD" -n "$NS"
capture events.txt get events -n "$NS" --field-selector "involvedObject.name=${POD}" -o wide
if [[ "$DRY_RUN" -eq 0 ]]; then
  (cd "$OUT" && sha256sum ./*.txt >SHA256SUMS)
  echo "logs saved to ${OUT}"
fi
