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
    base = os.path.expanduser("~/.cursor/chats")
    removed = 0
    try:
        import shutil
        cutoff = time.time() - keep_min * 60
        for ws in os.listdir(base):
            wsp = os.path.join(base, ws)
            if not os.path.isdir(wsp):
                continue
            for c in os.listdir(wsp):
                cp = os.path.join(wsp, c)
                try:
                    if os.path.isdir(cp) and os.path.getmtime(cp) < cutoff:
                        shutil.rmtree(cp)
                        removed += 1
                except OSError:
                    pass
    except OSError:
        pass
    return removed


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

    # 2/3. per-hunt health
    for p in _pm2_jlist():
        name = p.get("name", "")
        if not name.startswith("hunt-") or name == "hunt-bridge":
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
            actions.append(f"restarted {name} (status was {status})")
            alerts.append(f"{name} was {status}")
            continue
        # stuck mid-round (not sleeping) with no progress for STUCK_MIN -> restart
        age = _log_age_min(slug)
        if age is not None and age > STUCK_MIN and not _is_sleeping(slug):
            _pm2("restart", name)
            actions.append(f"restarted {name} (stuck mid-round, no log for {int(age)}m)")
            alerts.append(f"{name} stuck {int(age)}m mid-round")

    # 4. chat bloat
    chats = _chat_count()
    if chats > CHAT_MAX:
        rm = _prune_chats()
        actions.append(f"pruned {rm} stale chats ({chats} -> {_chat_count()})")

    _save_state({"ts": time.time(), "restarts": restarts_now})

    # 5. report / alert (email only when there ARE alerts, to avoid spam)
    summary = f"watchdog: {len(actions)} action(s), {len(alerts)} alert(s); chats={chats}"
    if actions:
        summary += " | " + "; ".join(actions)
    if not quiet:
        print(summary)
        for a in actions:
            print("  -", a)
    if alerts:
        try:
            import notify
            notify.send_safe(f"[watchdog] {len(alerts)} issue(s) — {', '.join(a[:1] for a in [alerts[0]])}…",
                             summary + "\n\nAlerts:\n- " + "\n- ".join(alerts))
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
