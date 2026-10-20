#!/usr/bin/env bash
# Send a short incident notification to Slack and/or Teams.
# Webhook URLs are read ONLY from SLACK_WEBHOOK_URL / TEAMS_WEBHOOK_URL (never pass them as args).
# Usage: notify.sh "<message>" [--dry-run]
set -euo pipefail

MSG="${1:-}"; DRY_RUN=0
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=1
[[ -n "$MSG" ]] || { echo "usage: $0 \"<message>\" [--dry-run]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

post() { # post <name> <url> <json>
  local name="$1" url="$2" body="$3"
  [[ "$url" == https://* ]] || { echo "$name webhook must be https" >&2; return 1; }
  if [[ "$DRY_RUN" -eq 1 ]]; then echo "[dry-run] POST $name: $body"; return 0; fi
  curl -fsS --max-time 10 -H 'Content-Type: application/json' -d "$body" "$url" >/dev/null
  echo "sent to $name"
}

sent=0
if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  post slack "$SLACK_WEBHOOK_URL" "$(jq -n --arg t ":rotating_light: $MSG" '{text:$t}')"; sent=1
fi
if [[ -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
  post teams "$TEAMS_WEBHOOK_URL" "$(jq -n --arg t "$MSG" '{type:"message",attachments:[{contentType:"application/vnd.microsoft.card.adaptive",content:{type:"AdaptiveCard",version:"1.4",body:[{type:"TextBlock",wrap:true,weight:"Bolder",text:$t}]}}]}')"; sent=1
fi
[[ "$sent" -eq 1 ]] || echo "no SLACK_WEBHOOK_URL / TEAMS_WEBHOOK_URL set - nothing sent" >&2
