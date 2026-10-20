#!/usr/bin/env bash
# Quarantine a compromised pod: deny-all NetworkPolicy + quarantine label + detach from controller.
# Usage: isolate-pod.sh -n <namespace> -p <pod> [-i <incident-id>] [--dry-run]
set -euo pipefail

NS="" POD="" INCIDENT="IR-$(date -u +%Y%m%d-%H%M%S)" DRY_RUN=0

usage() { echo "usage: $0 -n <namespace> -p <pod> [-i <incident-id>] [--dry-run]" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) NS="${2:-}"; shift 2 ;;
    -p) POD="${2:-}"; shift 2 ;;
    -i) INCIDENT="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done
[[ -n "$NS" && -n "$POD" ]] || usage
[[ "$NS" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && "$POD" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || { echo "invalid name" >&2; exit 2; }

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then printf '[dry-run] %q ' "$@"; echo; else "$@"; fi
}

policy=$(cat <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-deny-all
  namespace: ${NS}
spec:
  podSelector:
    matchLabels:
      security.csb.io/quarantine: "true"
  policyTypes: ["Ingress", "Egress"]
YAML
)

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] kubectl apply -f - <<< (quarantine-deny-all in ${NS})"
else
  kubectl apply -f - <<<"$policy"
fi
run kubectl label pod "$POD" -n "$NS" security.csb.io/quarantine=true --overwrite
run kubectl annotate pod "$POD" -n "$NS" "security.csb.io/incident-id=${INCIDENT}" --overwrite
run kubectl label pod "$POD" -n "$NS" app.kubernetes.io/name-
echo "[$(date -u +%FT%TZ)] ${POD} in ${NS} isolated (incident ${INCIDENT})"
