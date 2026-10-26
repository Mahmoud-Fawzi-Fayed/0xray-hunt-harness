#!/usr/bin/env bash
# Persistent, crash-safe hunt launcher. Run under pm2 so the OS process auto-restarts on crash/OOM/kill;
# the engine's state is persisted every step, so a restart RESUMES where it left off.
#
#   pm2 start ~/0xray-hunt-harness/harness/hunt-run.sh --name hunt-<target> -- <scope.json> [interval_s]
#   pm2 logs hunt-<target>        # watch it
#   pm2 stop  hunt-<target>       # pause   ·   pm2 delete hunt-<target>  # stop for good
#
# Layers of resilience:
#   1) engine runs each phase in try/except (one phase failing doesn't abort the round)
#   2) orchestrator --persist catches a crashing round, backs off, and keeps hunting (never "no vuln" stop)
#   3) pm2 restarts the whole process if it dies, and the run resumes from saved state
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
set -a; [ -f "$HERE/.env" ] && . "$HERE/.env"; set +a
SCOPE="${1:?usage: hunt-run.sh <scope.json> [interval_seconds]}"
INTERVAL="${2:-1800}"
cd ~/0xray-hunt-harness/engine
exec python3 engine/orchestrator.py --scope "$SCOPE" --hunt --persist --interval "$INTERVAL"
