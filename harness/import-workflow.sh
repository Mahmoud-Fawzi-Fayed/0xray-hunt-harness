#!/usr/bin/env bash
# Inject the bridge token/URL into a workflow template and import it into the hunt-n8n container.
# Usage: ./import-workflow.sh [workflows/novelty-monitor.json]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
set -a; . "$HERE/.env"; set +a
SRC="${1:-$HERE/workflows/novelty-monitor.json}"
TMP="$(mktemp -d)"
sed "s|__HUNT_BRIDGE_TOKEN__|${HUNT_BRIDGE_TOKEN}|g; s|__HUNT_BRIDGE_URL__|${HUNT_BRIDGE_URL}|g" \
  "$SRC" > "$TMP/wf.json"
docker cp "$TMP/wf.json" hunt-n8n:/tmp/wf.json
docker exec hunt-n8n n8n import:workflow --input=/tmp/wf.json
rm -rf "$TMP"
echo "imported $(basename "$SRC") -> hunt-n8n (inactive; add SMTP creds + activate in the UI to enable email)"
