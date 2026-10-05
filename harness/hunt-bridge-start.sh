#!/usr/bin/env bash
# Host-side hunt-bridge launcher (kept alive by pm2). Sources .env for the token + base.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
set -a; [ -f "$HERE/.env" ] && . "$HERE/.env"; set +a
exec python3 /root/Claude-BugHunter/engine/bridge.py \
  --port "${BRIDGE_PORT:-8899}" --base "${BUGHUNTER_BASE:-/root/.bughunter-engagements}"
