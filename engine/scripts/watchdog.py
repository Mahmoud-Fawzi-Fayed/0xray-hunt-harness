#!/usr/bin/env python3
"""
watchdog.py — periodic health check + self-heal for the hunt harness. Runs on a schedule (pm2 cron) and:

  - bridge down            -> restart hunt-bridge
  - a managed hunt not online (crashed/errored/stopped unexpectedly) -> restart it
  - a hunt stuck MID-ROUND (no log progress for STUCK_MIN while not sleeping) -> restart it
  - chat sessions ballooning (> CHAT_MAX) -> prune stale ones (keep the active pool)
  - crash-loop (restarts jumped a lot since last check) -> email alert
  - anything anomalous -> one concise email (never spams: only on change)

It only RESTARTS hunts that already exist in pm2 (it never starts new targets you didn't launch), and it
is conservative about "stuck" (sleeping between rounds is normal, not stuck). Safe to run every 10-15 min.

  python3 scripts/watchdog.py            # one pass
  python3 scripts/watchdog.py --quiet    # no stdout (for cron)
"""
import argparse
import json
import os
import subprocess
import sys
import time

ENGINE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine")
sys.path.insert(0, ENGINE)

BASE = os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements"))
STATE = os.path.join(BASE, "_watchdog.json")
STUCK_MIN = int(os.environ.get("WATCHDOG_STUCK_MIN", "45"))      # mid-round no-progress minutes => restart
CHAT_MAX = int(os.environ.get("WATCHDOG_CHAT_MAX", "60"))        # prune chats above this
# --- dynamic capacity governor: size the running hunt suite to THIS box (no thrash) ---
CORES = os.cpu_count() or 2
MAX_HUNTS_BOX = int(os.environ.get("WATCHDOG_MAX_HUNTS_BOX", str(max(1, CORES + 1))))  # suite size for this box
LOAD_CEIL = float(os.environ.get("WATCHDOG_LOAD_CEIL", str(CORES * 4)))                # 15m-load overload line
HUNT_PRIORITY = [p.strip() for p in os.environ.get(
    "WATCHDOG_HUNT_PRIORITY", "reddit,paysafe,vinted,dransay,wyylde").split(",") if p.strip()]
BRIDGE = "http://127.0.0.1:8899"
PM2 = __import__("shutil").which("pm2") or "/usr/bin/pm2"
# a last log line starting with one of these means the hunt is BETWEEN rounds (sleeping), not stuck
IDLE_MARKERS = ("orchestrator done", "orchestrator:", "persist:", "draft-gate:", "=== persist round")


def _pm2_jlist():
    try:
        r = subprocess.run([PM2, "jlist"], capture_output=True, text=True, timeout=20)
        return json.loads(r.stdout)
    except Exception:  # noqa: BLE001
        return []


def _pm2(*args):
    try:
        subprocess.run([PM2, *args], capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001
        pass


def _bridge_ok():
    import urllib.request
    try:
        with urllib.request.urlopen(BRIDGE + "/health", timeout=8) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def _log_age_min(slug):
    lg = os.path.join(BASE, slug, "engine.log")
    try:
        return (time.time() - os.path.getmtime(lg)) / 60.0
    except OSError:
        return None


def _last_line(slug):
    lg = os.path.join(BASE, slug, "engine.log")
    try:
        with open(lg, "rb") as fh:
            fh.seek(max(0, os.path.getsize(lg) - 4000))
            return fh.read().decode("utf-8", "replace").splitlines()[-1]
    except Exception:  # noqa: BLE001
        return ""


def _is_sleeping(slug):
    line = _last_line(slug)
    return any(m in line for m in IDLE_MARKERS)


def _chat_count():
    base = os.path.expanduser("~/.cursor/chats")
    n = 0
    try:
        for ws in os.listdir(base):
            wsp = os.path.join(base, ws)
            if os.path.isdir(wsp):
                n += sum(1 for c in os.listdir(wsp) if os.path.isdir(os.path.join(wsp, c)))
    except OSError:
        pass
    return n


def _prune_chats(keep_min=30):
    """Prune ONLY harness-created sessions (recorded by the engine in the created-id registry), and
    only when they are no longer in any active hunt pool AND are stale. The operator's interactive /
    IDE sessions are never in the registry, so they are NEVER deleted here — even in the harness
    workspace. Delegates to the guarded sessions.clear_harness (the one sanctioned deletion path)."""
    try:
        import sessions as SESS
    except Exception:  # noqa: BLE001
        return 0
    try:
        r = SESS.clear_harness(
            base=BASE,
            stale_min=int(os.environ.get("WATCHDOG_STALE_MIN", str(keep_min))),
            confirm=True,
        )
        return r.get("removed", 0)
    except Exception:  # noqa: BLE001
        return 0


def _load_state():
    try:
        return json.load(open(STATE))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(s):
    try:
        os.makedirs(BASE, exist_ok=True)
        json.dump(s, open(STATE, "w"))
    except OSError:
        pass


def run_once(quiet=False):
    actions, alerts = [], []
    prev = _load_state()
    prev_restarts = prev.get("restarts", {})
    restarts_now = {}

    # 1. bridge
    if not _bridge_ok():
        _pm2("restart", "hunt-bridge")
        actions.append("restarted hunt-bridge (was down)")
        alerts.append("bridge was DOWN")

    # 1b. GOVERNOR — size the running hunt suite to THIS box (dynamic). Shed the lowest-priority excess
    # (by WATCHDOG_HUNT_PRIORITY) so a small box never thrashes; the operator is told on-site. Runs BEFORE
    # the restart loop so a shed hunt is not immediately revived. Raise WATCHDOG_MAX_HUNTS_BOX for a bigger box.
    online = [p.get("name", "")[5:] for p in _pm2_jlist()
              if p.get("name", "").startswith("hunt-") and p.get("name") not in ("hunt-bridge", "hunt-watchdog")
              and (p.get("pm2_env", {}) or {}).get("status") == "online"]
    if len(online) > MAX_HUNTS_BOX:
        ranked = [s for s in HUNT_PRIORITY if s in online] + [s for s in online if s not in HUNT_PRIORITY]
        for slug in ranked[MAX_HUNTS_BOX:]:
            _pm2("delete", "hunt-" + slug)          # delete (not stop) so the restart loop won't revive it
            actions.append(f"governor: suite capped at {MAX_HUNTS_BOX} for {CORES}-core box — stopped hunt-{slug}")
            alerts.append(f"suite over capacity on {CORES} cores — stopped hunt-{slug} "
                          f"(box max {MAX_HUNTS_BOX}; raise WATCHDOG_MAX_HUNTS_BOX or use a bigger box)")

    # 2/3. per-hunt health
    revived = dict(prev.get("revived", {}))     # hunts THE WATCHDOG itself restarted (not manual/pm2 restarts)
    for p in _pm2_jlist():
        name = p.get("name", "")
        if not name.startswith("hunt-") or name in ("hunt-bridge", "hunt-watchdog"):
            continue
        slug = name[5:]
        env = p.get("pm2_env", {}) or {}
        status = env.get("status")
        restarts_now[name] = env.get("restart_time", 0)
        # crash-loop: restarts climbed a lot since last pass
        if name in prev_restarts and restarts_now[name] - prev_restarts[name] >= 5:
            alerts.append(f"{name} restarted {restarts_now[name]-prev_restarts[name]}x since last check (crash-loop?)")
        # not online -> restart
        if status != "online":
            _pm2("restart", name)
            revived[name] = revived.get(name, 0) + 1
            actions.append(f"restarted {name} (status was {status})")
            alerts.append(f"{name} was {status}")
            continue
        # stuck mid-round (not sleeping) with no progress for STUCK_MIN -> restart
        age = _log_age_min(slug)
        if age is not None and age > STUCK_MIN and not _is_sleeping(slug):
            _pm2("restart", name)
            revived[name] = revived.get(name, 0) + 1
            actions.append(f"restarted {name} (stuck mid-round, no log for {int(age)}m)")
            alerts.append(f"{name} stuck {int(age)}m mid-round")

    # 4. chat bloat — prune ONLY harness-created sessions (never the operator's own sessions).
    # Safe to run every pass now (registry + pool guarded), so the store stays tidy without ever
    # waiting for a CHAT_MAX threshold that would otherwise tempt a blunt age-based delete.
    chats = _chat_count()
    rm = _prune_chats()
    if rm:
        actions.append(f"pruned {rm} harness session(s) ({chats} -> {_chat_count()})")
    elif chats > CHAT_MAX:
        alerts.append(f"chat store at {chats} (> {CHAT_MAX}) but only operator sessions are prunable-exempt; "
                      f"run `python3 engine/sessions.py clear --all` to review husks/orphans")

    # overload notice (dynamic, box-aware) — if the 15-min load is above the ceiling, agents are likely
    # timing out; tell the operator on-site to run fewer programs or move to a bigger box.
    try:
        load15 = os.getloadavg()[2]
    except Exception:  # noqa: BLE001
        load15 = 0.0
    if load15 > LOAD_CEIL:
        alerts.append(f"overloaded: 15-min load {load15:.1f} > {LOAD_CEIL:.0f} on {CORES} cores — "
                      f"fewer programs or a bigger box (hunts may be timing out)")

    # de-dupe alerts vs last tick (by category, ignoring the changing numbers) so the panel + email are
    # NOT spammed with the same notice every 15 minutes — a condition re-alerts only after it clears.
    import re as _re
    def _akey(a):
        return _re.sub(r"[0-9].*$", "", str(a)).strip()[:48]
    prev_keys = set(prev.get("alert_keys", []))
    cur_keys = sorted({_akey(a) for a in alerts})
    new_alerts = [a for a in alerts if _akey(a) not in prev_keys]
    _save_state({"ts": time.time(), "restarts": restarts_now, "revived": revived, "alert_keys": cur_keys})

    # 5. report / alert — the ON-SITE feed (panel) is the primary surface; only NEW alerts are pushed.
    summary = f"watchdog: {len(actions)} action(s), {len(alerts)} alert(s) ({len(new_alerts)} new); chats={chats}"
    if actions:
        summary += " | " + "; ".join(actions)
    if not quiet:
        print(summary)
        for a in actions:
            print("  -", a)
    if new_alerts:
        try:
            import notify
            for a in new_alerts:                   # ON-SITE (panel feed) — the operator's primary surface
                notify.site_alert("watchdog", [a], base=BASE, kind="watchdog")
            notify.send_safe(f"[watchdog] {len(new_alerts)} issue(s) — {new_alerts[0][:60]}…",
                             summary + "\n\nNew alerts:\n- " + "\n- ".join(new_alerts))
        except Exception:  # noqa: BLE001
            pass
    # append to a small watchdog log
    try:
        with open(os.path.join(BASE, "_watchdog.log"), "a") as fh:
            fh.write(time.strftime("%Y-%m-%dT%H:%M:%S") + "  " + summary + "\n")
    except OSError:
        pass
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="hunt harness health watchdog")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    return run_once(quiet=a.quiet)


if __name__ == "__main__":
    sys.exit(main())
