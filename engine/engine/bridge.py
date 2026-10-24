#!/usr/bin/env python3
"""
bridge.py — host-side hunt-bridge for the n8n monitor (and, later, the orchestrator).

n8n runs in Docker and cannot reach the host's recon tools or this engine. The bridge is the
thin seam: n8n owns scheduling + routing + email; the bridge does the actual work on the host
(observe a target's surface, diff it with novelty.py, score candidates with dedup.py) and writes
the local alerts feed. Loopback-only + token-authed, so nothing off-box can trigger recon.

Endpoints (all POST take JSON; all except /health require header `X-Hunt-Token: <token>`):
  GET  /health                      -> {ok, ts, version}
  POST /novelty/watch  {target, obs?}   -> observe (or use supplied obs), diff vs last, ADVANCE
                                           baseline, append to alerts feed on change. Returns diff+summary.
  POST /novelty/diff   {target, obs?}   -> diff only (no baseline advance, no feed write).
  POST /dedup/check    {program, class, url, title}  -> {verdict, score, matches}
  POST /dedup/ingest   {program, source, items|reports}  -> {added}
  POST /disposition/check {finding|text, program?}  -> {verdict: PASS|HOLD_RTFS|HOLD_INFORMATIVE, draft, rules, reason}
  GET  /novelty/feed?n=20            -> last n alert feed entries

Run (kept alive by pm2 in the harness):
  HUNT_BRIDGE_TOKEN=xxx python3 engine/bridge.py --host 127.0.0.1 --port 8899
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dedup as D        # noqa: E402
import novelty as N      # noqa: E402
import observe as O      # noqa: E402
import notify as NO      # noqa: E402

ENGINE = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.6"
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
TOKEN = os.environ.get("HUNT_BRIDGE_TOKEN", "")
MAX_BODY = int(os.environ.get("HUNT_BRIDGE_MAX_BODY", str(2 * 1024 * 1024)))   # 2 MB general request cap
VERIFY_MAX_BODY = int(os.environ.get("HUNT_VERIFY_MAX_BODY", str(32 * 1024 * 1024)))  # /verify accepts file uploads

# Background snapshot so /stats /hunt/status /activity /capabilities NEVER call pm2/ps on the
# request path. Panel polls every 8s; a cache-miss stampede of `pm2 jlist` + `ps -eo args` filled
# the accept queue and the site showed "bridge offline" with empty counters.
_BG = {"hunts": [], "activity": {"events": [], "models": {}},
       "stats": {"targets": 0, "running": 0, "findings": 0, "alerts": 0},
       "caps": None, "ts": 0.0, "ok": False}
_BG_LOCK = threading.Lock()
_BG_BUSY = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _alerts_path(base):
    d = os.path.join(os.path.expanduser(base), "_alerts")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "feed.jsonl")


def _append_alert(base, entry):
    with open(_alerts_path(base), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


import shutil as _shutil
HUNT_RUN_SH = os.environ.get("HUNT_RUN_SH", "/root/BugHunting_0xRay/harness/hunt-run.sh")
PM2 = _shutil.which("pm2") or "/usr/bin/pm2"


def _pm2(args, timeout=25):
    import subprocess
    try:
        return subprocess.run([PM2, *args], capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _hunt_running(base):
    """Request-path: last background snapshot. Never blocks on pm2."""
    with _BG_LOCK:
        return list(_BG.get("hunts") or [])


def _hunts_from_pidfiles(base):
    """Instant running-hunt list from ~/.pm2/pids — no pm2 jlist (that call wedges under load)."""
    import glob as _g
    out = []
    for pf in _g.glob(os.path.expanduser("~/.pm2/pids/hunt-*.pid")):
        bn = os.path.basename(pf)
        m = re.match(r"(hunt-.+)-\d+\.pid$", bn)
        if not m:
            continue
        name = m.group(1)
        if name in ("hunt-bridge", "hunt-watchdog"):
            continue
        slug = name[5:]
        try:
            pid = int((open(pf).read() or "0").strip() or 0)
        except (OSError, ValueError):
            pid = 0
        running = bool(pid and os.path.exists(f"/proc/{pid}"))
        age, sleeping, interval_m = None, False, 180
        logf = os.path.join(os.path.expanduser(base), slug, "engine.log")
        idle = ("orchestrator done", "orchestrator:", "persist:", "draft-gate:", "=== persist round")
        try:
            age = int(time.time() - os.path.getmtime(logf))
            tail = _tail_bytes(logf, 4096).strip().splitlines()
            last = tail[-1].split("  ", 1)[-1] if tail else ""
            sleeping = any(last.startswith(x) for x in idle)
        except OSError:
            pass
        wd = 0
        try:
            wd = ((json.load(open(os.path.join(os.path.expanduser(base), "_watchdog.json"))) or {})
                  .get("revived") or {}).get(name, 0)
        except Exception:  # noqa: BLE001
            pass
        out.append({"program": slug, "pid": pid or None, "running": running, "restarts": 0,
                    "wd_restarts": wd, "log_age_s": age, "sleeping": sleeping,
                    "interval_m": interval_m})
    return out


def _hunt_running_compute(base):
    """Panel hunt list. Pid-files only — `pm2 jlist` is too slow on this box and used to wedge :8899."""
    found = _hunts_from_pidfiles(base)
    return found or list(_BG.get("hunts") or [])


def _tail_bytes(path, nbytes=524288):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - nbytes))
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _tail_lines(path, n, approx=220):
    """Last n lines without reading the whole file (superhuman engine.log is multiple MB)."""
    raw = _tail_bytes(path, max(65536, min(2 * 1024 * 1024, int(n) * int(approx))))
    lines = raw.splitlines()
    return lines[-n:] if n < len(lines) else lines


# destatic deep hunts log `hunt: deep-pentest URL (analysis-driven) model=…` — the old
# `class@url model= skills=[…]` regex matched none of the current tails, so the panel
# showed "no hunt steps yet" even when hunts were running.
_HUNT_SKILLS = re.compile(
    r"^(\S+)\s+hunt:\s+([a-z0-9_-]+)@(https?://\S+)\s+model=(\S+)\s+skills=\[([^\]]*)\]")
_HUNT_DEEP = re.compile(
    r"^(\S+)\s+hunt:\s+deep-pentest\s+(https?://\S+)\s+\(analysis-driven\)\s+model=(\S+)")
_HUNT_NOTHING = re.compile(
    r"^(\S+)\s+hunt:\s+nothing on ([a-z0-9_-]+)@(https?://\S+)")
_HUNT_TIMEOUT = re.compile(
    r"^(\S+)\s+hunt:\s+timeout on ([a-z0-9_-]+)@(https?://\S+)\s+\(model ([^)]+)\)")
_HUNT_ERROR = re.compile(
    r"^(\S+)\s+hunt:\s+error on ([a-z0-9_-]+)@(https?://\S+)\s+\(([^)]*)\)")
_HUNT_CAND = re.compile(
    r"^(\S+)\s+hunt:\s+(?:⚠ )?CANDIDATE ([a-z0-9_-]+) @ (\S+)")
_VAL_STEP = re.compile(
    r"^(\S+)\s+validate:\s+([a-z0-9_-]+)@(https?://\S+)\s+model=(\S+)")
_VAL_CONF = re.compile(
    r"^(\S+)\s+validate:\s+CONFIRMED (\S+) @ (\S+) \((\w+)\)")


def _activity_event(line, program):
    m = _HUNT_SKILLS.search(line)
    if m:
        ts, cls, url, model, sk = m.groups()
        return {"ts": ts, "program": program, "phase": "hunt", "class": cls, "url": url,
                "model": model, "skills": [s for s in sk.split(",") if s]}
    m = _HUNT_DEEP.search(line)
    if m:
        ts, url, model = m.groups()
        return {"ts": ts, "program": program, "phase": "hunt", "class": "deep", "url": url,
                "model": model, "skills": []}
    m = _HUNT_TIMEOUT.search(line)
    if m:
        ts, cls, url, model = m.groups()
        return {"ts": ts, "program": program, "phase": "hunt", "class": cls, "url": url,
                "model": model.strip(), "skills": []}
    m = _HUNT_ERROR.search(line)
    if m:
        ts, cls, url, err = m.groups()
        return {"ts": ts, "program": program, "phase": "hunt", "class": cls, "url": url,
                "model": "", "skills": [], "error": err}
    m = _HUNT_NOTHING.search(line)
    if m:
        ts, cls, url = m.groups()
        return {"ts": ts, "program": program, "phase": "hunt", "class": cls, "url": url,
                "model": "", "skills": []}
    m = _HUNT_CAND.search(line)
    if m:
        ts, cls, url = m.groups()
        return {"ts": ts, "program": program, "phase": "hunt", "class": cls, "url": url,
                "model": "", "skills": []}
    m = _VAL_CONF.search(line)
    if m:
        ts, cls, url, sev = m.groups()
        return {"ts": ts, "program": program, "phase": "confirmed", "class": cls, "url": url,
                "model": "", "skills": [], "severity": sev}
    m = _VAL_STEP.search(line)
    if m:
        ts, cls, url, model = m.groups()
        return {"ts": ts, "program": program, "phase": "validate", "class": cls, "url": url,
                "model": model, "skills": []}
    return None


def _activity_compute(base, n=200, program=""):
    import glob as _glob
    base = os.path.expanduser(base)
    if program:
        import targets as T
        logs = [os.path.join(base, T._slug(program), "engine.log")]
    else:
        logs = _glob.glob(os.path.join(base, "*", "engine.log"))
    events, models = [], {}
    for lg in logs:
        if not os.path.isfile(lg):
            continue
        pn = os.path.basename(os.path.dirname(lg))
        for line in _tail_bytes(lg, 524288).splitlines():
            ev = _activity_event(line, pn)
            if not ev:
                continue
            events.append(ev)
            m = ev.get("model") or ""
            if m and m != "pool":
                models[m] = models.get(m, 0) + 1
            elif m == "pool":
                models[m] = models.get(m, 0) + 1
    events.sort(key=lambda e: e["ts"], reverse=True)
    return {"events": events[:n], "models": models}


def _stats_compute(base, hunts):
    import targets as T
    wd = os.environ.get("HUNT_WEB_DIR")
    nf = 0
    if wd and os.path.isdir(wd):
        try:
            nf = len([f for f in os.listdir(wd) if f.startswith("finding-") and f.endswith(".html")])
        except OSError:
            nf = 0
    ap = os.path.join(os.path.expanduser(base), "_alerts", "feed.jsonl")
    na = 0
    if os.path.isfile(ap):
        try:
            na = sum(1 for _ in open(ap, errors="ignore"))
        except OSError:
            na = 0
    return {"targets": len(T.all_targets(base)),
            "running": len([h for h in hunts if h.get("running")]),
            "findings": nf, "alerts": na}


def _agent_count():
    """How many cursor-agent --resume processes are alive. Reads /proc cmdline; never `ps -eo args`
    (that dump is multi-MB here because hunt prompts embed cookies, and it was stalling /health)."""
    import glob as _g
    n = 0
    for cmd in _g.glob("/proc/[0-9]*/cmdline"):
        try:
            raw = open(cmd, "rb").read()
        except OSError:
            continue
        if b"cursor-agent" in raw and b"--resume" in raw:
            n += 1
    return n


def _caps_compute(base):
    import sms as _SMS
    import learn as _L
    import guardrails as _G
    with _BG_LOCK:
        running = [h for h in (_BG.get("hunts") or []) if h.get("running")]
    return {
        "sessions": {"chats_on_disk": 0, "transcripts_on_disk": 0, "orphaned": 0,
                     "orphaned_chats": 0, "pool_dead_ids": 0, "pool_corrupt": 0,
                     "pool_per_target": int(os.environ.get("HUNT_SESSION_POOL", "3")),
                     "max_uses": int(os.environ.get("HUNT_SESSION_MAX_USES", "25")),
                     "agents_running": _agent_count(),
                     "pooled_in_use": 0,
                     "targets_running": len(running)},
        "websearch": {"ready": True, "provider": "duckduckgo-html"},
        "identity": {"ready": True, "provider": "mail.tm", "max_accounts": _G.max_accounts()},
        "sms": _SMS.status(),
        "learn": {"learned_skills": len(_L.learned_index()),
                  "gaps": len(_L.gaps(base)), "journal": len(_L.journal(base))},
        "guardrails": {"no_bruteforce": True, "scope_enforced": True,
                       "max_accounts_per_program": _G.max_accounts()}}


def _bg_refresh_once(base, with_caps=True):
    if not _BG_BUSY.acquire(blocking=False):
        return
    try:
        hunts = _hunt_running_compute(base)
        with _BG_LOCK:
            _BG["hunts"] = hunts
        act = _activity_compute(base, n=200)
        stats = _stats_compute(base, hunts)
        caps = None
        if with_caps:
            try:
                caps = _caps_compute(base)
            except Exception as e:  # noqa: BLE001
                print(f"hunt-bridge: caps refresh failed: {type(e).__name__}: {e}", flush=True)
        with _BG_LOCK:
            _BG["hunts"] = hunts
            _BG["activity"] = act
            _BG["stats"] = stats
            if caps is not None:
                _BG["caps"] = caps
            _BG["ts"] = time.time()
            _BG["ok"] = True
    except Exception as e:  # noqa: BLE001
        print(f"hunt-bridge: background refresh failed: {type(e).__name__}: {e}", flush=True)
    finally:
        _BG_BUSY.release()


def _bg_loop(base):
    n = 0
    while True:
        n += 1
        _bg_refresh_once(base, with_caps=(n % 3 == 0))  # skip the first tick; ps/pm2 stay off the hot path
        time.sleep(8)


def _descendants(pid):
    """All descendant PIDs of pid (children, grandchildren, ...) — the target's cursor-agent sessions."""
    import subprocess
    out, frontier = [], [int(pid)]
    while frontier:
        p = frontier.pop()
        try:
            r = subprocess.run(["pgrep", "-P", str(p)], capture_output=True, text=True, timeout=5)
            kids = [int(x) for x in r.stdout.split()]
        except Exception:  # noqa: BLE001
            kids = []
        out += kids
        frontier += kids
    return out


def _hunt_pid(slug):
    r = _pm2(["jlist"])
    if not r or not r.stdout:
        return None
    try:
        for pr in json.loads(r.stdout):
            if pr.get("name") == "hunt-" + slug:
                return pr.get("pid") or (pr.get("pm2_env", {}) or {}).get("pid")
    except Exception:  # noqa: BLE001
        return None
    return None


def _stop_target_sessions(slug):
    """Kill the target's orchestrator AND all its cursor-agent session processes (no orphans left)."""
    pid = _hunt_pid(slug)
    killed = 0
    if pid:
        for d in _descendants(pid):
            try:
                os.killpg(os.getpgid(d), signal.SIGKILL)   # kill the session's whole group
            except Exception:  # noqa: BLE001
                try:
                    os.kill(d, signal.SIGKILL)
                except Exception:  # noqa: BLE001
                    pass
            killed += 1
    _pm2(["delete", "hunt-" + slug])
    _pm2(["save"])
    return killed


class Handler(BaseHTTPRequestHandler):
    base = DEFAULT_BASE
    server_version = f"hunt-bridge/{VERSION}"

    # ---- helpers ----
    def _send(self, code, obj):
        """Serialize + send a JSON response. Tolerates a client that hangs up mid-response — n8n and
        other pollers routinely drop the socket, which used to raise BrokenPipeError out of the handler
        thread and spam the log (and, on the error path, double-fault). A disconnect is now a quiet
        no-op: return False so callers never try to send a second response on a dead socket."""
        try:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            body, code = b'{"error":"unserializable response"}', 500
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return False   # client went away before we finished — nothing left to do

    def _send_raw(self, code, data, filename="file"):
        """Binary download response (fix-chat files). Same disconnect-tolerant behavior as _send."""
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return False

    def _authed(self):
        if not TOKEN:                       # fail-closed: refuse everything until a token is set
            self._send(503, {"error": "bridge has no HUNT_BRIDGE_TOKEN set"})
            return False
        if self.headers.get("X-Hunt-Token", "") != TOKEN:
            self._send(401, {"error": "bad or missing X-Hunt-Token"})
            return False
        return True

    def _body(self, cap=None):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(min(n, cap or MAX_BODY)) or b"{}")
        except json.JSONDecodeError:
            return {}

    def log_message(self, *a):            # quiet default access logging
        pass

    # ---- routing ----
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/health":
            return self._send(200, {"ok": True, "ts": _now(), "version": VERSION})
        if not self._authed():
            return
        try:
            if p.path == "/verify/fixchat/download":
                import fixchat as FC
                q = parse_qs(p.query)
                name, data = FC.read_file(q.get("chat_id", [""])[0], q.get("name", [""])[0],
                                          base=self.base)
                if data is None:
                    return self._send(404, {"error": "file not found"})
                return self._send_raw(200, data, filename=name)
            if p.path == "/verify/fixchat/status":
                import fixchat as FC
                q = parse_qs(p.query)
                r = FC.status(q.get("chat_id", [""])[0], base=self.base)
                return self._send(200 if not r.get("error") else 404, r)
            if p.path == "/verify/fixchat/list":
                import fixchat as FC
                return self._send(200, FC.list_chats(self.base))
            if p.path == "/novelty/feed":
                try:
                    n = max(1, min(1000, int((parse_qs(p.query).get("n", ["20"])[0]) or 20)))
                except (ValueError, TypeError):
                    n = 20
                path = _alerts_path(self.base)
                lines = open(path, encoding="utf-8").read().splitlines() if os.path.isfile(path) else []
                out = []
                for x in lines[-n:]:
                    if not x.strip():
                        continue
                    try:
                        out.append(json.loads(x))
                    except json.JSONDecodeError:
                        continue                      # skip a corrupt feed line, never 500
                return self._send(200, {"count": len(out), "entries": out})
            if p.path == "/targets":
                import targets as T
                return self._send(200, {"targets": T.monitor_list(self.base)})
            if p.path == "/targets/list":
                import targets as T
                return self._send(200, {"targets": T.all_targets(self.base)})
            if p.path == "/hunt/status":
                hunts = _hunt_running(self.base)
                wd = {}
                try:
                    wd = json.load(open(os.path.join(self.base, "_watchdog.json"))) or {}
                except Exception:  # noqa: BLE001
                    pass
                return self._send(200, {"hunts": hunts,
                                        "watchdog": {"ts": wd.get("ts"), "revived": wd.get("revived") or {}}})
            if p.path == "/review/latest":
                fp = os.path.join(os.path.expanduser(self.base), "_review", "latest.json")
                livep = os.path.join(os.path.expanduser(self.base), "_review", "live.json")
                try:
                    data = json.load(open(fp))
                except Exception:  # noqa: BLE001
                    data = {"error": "no review yet"}
                try:
                    live = json.load(open(livep))
                    if isinstance(data, dict):
                        data["live"] = live
                except Exception:  # noqa: BLE001
                    pass
                return self._send(200, data)
            if p.path == "/review/journal":
                fp = os.path.join(os.path.expanduser(self.base), "_review", "journal.jsonl")
                out = []
                if os.path.isfile(fp):
                    for ln in open(fp, encoding="utf-8").read().splitlines()[-50:]:
                        try:
                            out.append(json.loads(ln))
                        except json.JSONDecodeError:
                            continue
                return self._send(200, {"count": len(out), "entries": out})
            if p.path == "/hunt/log":
                import targets as T
                q = parse_qs(p.query)
                slug = T._slug(q.get("program", [""])[0])        # slug-only -> no path traversal
                try:
                    n = max(1, min(2000, int((q.get("n", ["300"])[0]) or 300)))
                except (ValueError, TypeError):
                    n = 300
                lines = []
                for path in (os.path.join(os.path.expanduser(self.base), slug, "engine.log"),
                             os.path.join(os.path.expanduser(self.base), f"hunt-{slug}.log")):
                    if os.path.isfile(path):
                        lines = _tail_lines(path, n)
                        break
                return self._send(200, {"program": slug, "lines": lines[-n:]})
            if p.path == "/findings/list":
                import findings as FD
                return self._send(200, {"findings": FD.list_findings(self.base),
                                        "summary": FD.summary(self.base), "statuses": FD.STATUSES})
            if p.path == "/findings":
                wd = os.environ.get("HUNT_WEB_DIR")
                base_url = (os.environ.get("HUNT_PUBLIC_URL") or "").rstrip("/")
                out = []
                if wd and os.path.isdir(wd):
                    for f in os.listdir(wd):
                        if f.startswith("finding-") and f.endswith(".html"):
                            fp = os.path.join(wd, f)
                            out.append({"file": f, "url": (base_url + "/" + f) if base_url else "",
                                        "mtime": int(os.path.getmtime(fp))})
                out.sort(key=lambda x: -x["mtime"])
                return self._send(200, {"findings": out})
            if p.path == "/stats":
                with _BG_LOCK:
                    s = dict(_BG.get("stats") or {})
                return self._send(200, s or {"targets": 0, "running": 0, "findings": 0, "alerts": 0})
            if p.path == "/activity":
                q = parse_qs(p.query)
                try:
                    n = max(1, min(400, int((q.get("n", ["80"])[0]) or 80)))
                except (ValueError, TypeError):
                    n = 80
                prog = (q.get("program", [""])[0] or "").strip()
                with _BG_LOCK:
                    payload = dict(_BG.get("activity") or {"events": [], "models": {}})
                events = list(payload.get("events") or [])
                if prog:
                    events = [e for e in events if e.get("program") == prog]
                return self._send(200, {"events": events[:n], "models": payload.get("models") or {}})
            if p.path == "/capabilities":
                with _BG_LOCK:
                    caps = _BG.get("caps")
                if not caps:
                    caps = {"sessions": {}, "websearch": {"ready": True, "provider": "duckduckgo-html"},
                            "identity": {"ready": True}, "sms": {"enabled": False},
                            "learn": {"learned_skills": 0, "gaps": 0, "journal": 0},
                            "guardrails": {"no_bruteforce": True, "scope_enforced": True}}
                return self._send(200, caps)
            if p.path == "/learn/journal":
                import learn as _L
                try:
                    n = max(1, min(500, int((parse_qs(p.query).get("n", ["60"])[0]) or 60)))
                except (ValueError, TypeError):
                    n = 60
                j = _L.journal(self.base)
                return self._send(200, {"count": len(j), "entries": j[-n:],
                                        "learned_skills": _L.learned_index()})
            if p.path == "/accounts":
                import guardrails as _G
                import targets as T
                q = parse_qs(p.query)
                prog = q.get("program", [""])[0]
                try:
                    n = max(1, min(1000, int((q.get("n", ["200"])[0]) or 200)))
                except (ValueError, TypeError):
                    n = 200
                audit = _G.read_audit(prog or None, n=n, base=self.base)
                counts = {t.get("name"): _G.account_count(t.get("name"), self.base)
                          for t in T.all_targets(self.base)}
                return self._send(200, {"audit": audit, "accounts_per_program": counts,
                                        "cap": _G.max_accounts()})
            if p.path == "/auth/list":
                import authsession as AS
                return self._send(200, {"sessions": AS.status(self.base)})
            if p.path == "/targets/rank":
                import yieldrank as YR
                running = []
                try:
                    jl = _pm2(["jlist"])
                    procs = json.loads(jl.stdout or "[]") if jl and jl.returncode == 0 else []
                    running = [x.get("name", "")[5:] for x in procs
                              if x.get("name", "").startswith("hunt-")
                              and x.get("name") not in ("hunt-bridge", "hunt-watchdog")
                              and (x.get("pm2_env", {}) or {}).get("status") == "online"]
                except Exception:  # noqa: BLE001
                    pass
                return self._send(200, {"running": running,
                                        "targets": YR.rank_targets(self.base, running=running, include_running=True)})
            if p.path == "/auth/check":
                import authsession as AS
                import targets as T
                prog = parse_qs(p.query).get("program", [""])[0]
                res = AS.check_live(prog, self.base)
                slug = T._slug(prog)
                logp = os.path.expanduser("~/.pm2/logs/hunt-" + slug + "-out.log")
                res["hunt_status"] = "no running hunt for this program"
                try:
                    tail = open(logp, encoding="utf-8", errors="ignore").readlines()[-5000:]
                    for line in reversed(tail):
                        if "AUTHENTICATED — using test session" in line:
                            res["hunt_status"] = "hunt is USING the session (log shows 'AUTHENTICATED')"; break
                        if "until a live session is pasted" in line:
                            res["hunt_status"] = "holding that host until a live session is pasted"; break
                        if "hunting unauthenticated" in line:
                            res["hunt_status"] = "hunt ran UNAUTHENTICATED last round — paste a live login"; break
                except OSError:
                    pass
                return self._send(200, res)
            return self._send(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return  # client (n8n/panel poller) hung up mid-response — benign, don't double-fault
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        if not self._authed():
            return
        p = urlparse(self.path)
        cap = VERIFY_MAX_BODY if p.path in ("/verify", "/verify/fixchat/start") else MAX_BODY
        clen = int(self.headers.get("Content-Length") or 0)
        if clen > cap:
            return self._send(413, {"error": f"body too large (> {cap} bytes)"})
        b = self._body(cap)
        try:
            if p.path == "/findings/mark":              # operator disposition -> stored + feeds the learning loop
                import findings as FD
                key = (b.get("key") or "").strip()
                status = (b.get("status") or "").strip().lower()
                if not key or not status:
                    return self._send(400, {"error": "key and status required"})
                try:
                    rec = FD.set_mark(self.base, key, status, b.get("note", ""))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"ok": True, "mark": rec})
            if p.path == "/review/run":                 # panel "Run now" — always a real pass, not the 40-min wait
                log = os.path.join(os.path.expanduser(self.base), "_review", "run.log")
                os.makedirs(os.path.dirname(log), exist_ok=True)
                lock = os.path.join(os.path.dirname(log), "review.lock")
                try:
                    if os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 1800:
                        return self._send(200, {"started": False,
                                                "reason": "a review is already running"})
                except OSError:
                    pass
                subprocess.Popen(["python3", os.path.join(ENGINE, "reviewer.py"), "--force", "--quiet"],
                                 start_new_session=True, stdout=open(log, "a"), stderr=subprocess.STDOUT)
                return self._send(200, {"started": True, "note": "review running now"})
            if p.path in ("/novelty/watch", "/novelty/diff"):
                target = b.get("target")
                if not target:
                    return self._send(400, {"error": "target required"})
                obs = b.get("obs") or O.observe(target, base=self.base, live=b.get("live", True),
                                                cap_hosts=8, cap_js=24, deadline_s=90)
                nv = N.Novelty(target, base=self.base)
                if p.path == "/novelty/diff":
                    diff = nv.diff(obs)
                    return self._send(200, {"diff": diff, "summary": N.summarize(diff)})
                diff = nv.watch(obs)                      # diff THEN advance baseline
                counts = {k: len(diff.get(k, [])) for k in diff if k.startswith(("new_", "changed_"))}
                alerted = False
                if diff.get("has_changes"):
                    _append_alert(self.base, {"ts": _now(), "target": target,
                                              "summary": N.summarize(diff), "counts": counts})
                    alerted = True
                return self._send(200, {"target": target, "has_changes": diff.get("has_changes", False),
                                        "baseline": diff.get("baseline", False), "counts": counts,
                                        "summary": N.summarize(diff), "alerted": alerted, "diff": diff})

            if p.path == "/dedup/check":
                res = D.Corpus(b.get("program", ""), base=self.base).check(
                    {"vuln_class": b.get("class") or b.get("vuln_class", ""),
                     "url": b.get("url", ""), "title": b.get("title", "")})
                return self._send(200, res)

            if p.path == "/dedup/ingest":
                items = b.get("items") or b.get("reports") or []
                added = D.Corpus(b.get("program", ""), base=self.base).ingest(items, source=b.get("source"))
                return self._send(200, {"added": added, "supplied": len(items)})

            if p.path == "/disposition/check":
                import disposition as DP
                form = b.get("finding") if isinstance(b.get("finding"), dict) else None
                if form is None and b.get("text"):
                    form = DP.from_text(b.get("text") or "")
                if form is None:
                    form = {k: v for k, v in b.items() if k != "program"}
                if b.get("program"):
                    form["program"] = b.get("program")
                return self._send(200, DP.check(form, program=b.get("program") or form.get("program"),
                                                base=self.base))

            if p.path == "/verify":
                import verify as V
                form = dict(b.get("finding") or b)
                prog = b.get("program") or form.get("program")
                files = b.get("files") or []
                intake = V.ingest_files(files, program=prog, base=self.base) if files else None
                parsed = V.extract_finding(intake["text"]) if (intake and intake.get("text")) else {}
                f = dict(parsed)
                for k in ("vuln_class", "severity", "url", "title", "steps", "poc", "impact", "evidence"):
                    if form.get(k):
                        f[k] = form[k]                 # an explicit form value overrides what we parsed from files
                if intake:
                    f["evidence"] = ((f.get("evidence", "") or "") + "\n" + intake["text"]).strip()
                    f["_images"] = intake["images"]
                    f["_files_dir"] = intake.get("dir")               # triager reads images/scripts from here
                    f["_file_names"] = [s["name"] for s in intake["saved"]]
                res = V.verify_finding(f, program=prog, base=self.base, live=bool(b.get("live", True)))
                res["extracted"] = {k: parsed[k] for k in ("vuln_class", "severity", "url", "title") if parsed.get(k)}
                if intake:
                    res["uploads"] = {"saved": [s["name"] for s in intake["saved"]],
                                      "rejected": intake["rejected"], "images": intake["images"]}
                op = None
                if b.get("deep"):
                    op = V.deep_opinion_all(f, res, program=prog, base=self.base)   # one triager per pool model
                    res["triager_opinion"] = op
                    if op.get("verdict"):
                        res["verdict"] = V.combine_verdict(res, op)  # strictest across ALL models + the gate
                        res["accept"] = res["verdict"] == "READY"
                res["summary"] = V._summarize(res, op)               # brief reflects the FINAL verdict
                # REAL BUG = reproduced with impact (a model actively re-ran it, or the deterministic live
                # re-test confirmed it) AND it isn't rejected. This is the dynamic real-vs-not signal.
                _live_ok = (res.get("live") or {}).get("confirmed") is True
                res["reproduced"] = bool((op or {}).get("real_bug") or _live_ok)
                res["real_bug"] = bool(res.get("verdict") == "READY"
                                       and ((op or {}).get("real_bug") or _live_ok))
                # verify-only hygiene: remove the uploaded files + the ephemeral triager chat sessions
                try:
                    V._cleanup(paths=[intake["dir"]] if intake and intake.get("dir") else [],
                               session_ids=(op or {}).get("session_ids") or [])
                    res["cleaned"] = True
                except Exception:  # noqa: BLE001
                    res["cleaned"] = False
                return self._send(200, res)

            if p.path == "/sessions/clear":
                import sessions as _SESS
                r = _SESS.clear_orphans(self.base, confirm=bool(b.get("confirm")))
                return self._send(200, r)

            if p.path == "/verify/fixchat/start":
                import fixchat as FC
                r = FC.start_async(b.get("program") or (b.get("finding") or {}).get("program"),
                                   b.get("finding") or {}, b.get("files") or [],
                                   b.get("verify") or {}, base=self.base, chat_id=b.get("chat_id"))
                return self._send(200, r)

            if p.path == "/verify/fixchat/message":
                import fixchat as FC
                r = FC.message_async(b.get("chat_id", ""), b.get("message", ""), base=self.base)
                return self._send(200 if not r.get("error") else 404, r)

            if p.path == "/verify/fixchat/close":
                import fixchat as FC
                r = FC.close(b.get("chat_id", ""), base=self.base)
                return self._send(200 if not r.get("error") else 404, r)

            if p.path == "/sessions/doctor":
                import sessions as _SESS
                r = _SESS.doctor(self.base, confirm=bool(b.get("confirm")))
                return self._send(200, r)

            if p.path == "/sessions/reset":
                import sessions as _SESS
                r = _SESS.reset_target(b.get("program", ""), self.base, confirm=bool(b.get("confirm")))
                code = 200 if not r.get("error") else 400
                return self._send(code, r)

            if p.path == "/notify":
                subj = b.get("subject", "(no subject)")
                # Email is reserved for FINDINGS. Surface/novelty alerts (the novelty monitor's
                # "new surface on X") are on-site only — /novelty/watch already wrote them to the
                # alert feed (panel bell). Opt back in per-call with {"email": true} / {"kind":
                # "finding"}, or globally with HUNT_EMAIL_SURFACE=1.
                is_surface = ("new surface" in subj.lower()) or (b.get("kind") in ("surface", "novelty"))
                opt_in = (bool(b.get("email")) or b.get("kind") == "finding"
                          or os.environ.get("HUNT_EMAIL_SURFACE") == "1")
                if is_surface and not opt_in:
                    return self._send(200, {"sent": False, "suppressed": "surface",
                                            "note": "surface alerts are on-site only; email is reserved for findings"})
                ok = NO.send_safe(subj, b.get("body", ""),
                                  to=b.get("to"), cc=b.get("cc"), html=b.get("html"))
                return self._send(200, {"sent": ok, "configured": NO.configured()})

            if p.path == "/hunt":
                # n8n / the panel trigger a Cursor-agent hunt. Real hunts run under pm2 so they survive
                # bridge restarts + auto-restart on crash; mock runs inline for testing.
                import targets as T
                prog = b.get("program", "")
                sc = T.load(prog, base=self.base)
                if not sc:
                    return self._send(404, {"error": f"unknown program: {prog} (add it first)"})
                slug = T._slug(prog)
                scope_path = os.path.join(os.path.expanduser(self.base), "_targets", slug + ".json")
                interval = str(int(b.get("interval", 1800)))
                # admission control: size the running suite to THIS box (cores+1). Reject a NEW program
                # that would exceed capacity, so >N is blocked AT START, not accepted-then-shed 15 min later.
                try:
                    cap = int(os.environ.get("WATCHDOG_MAX_HUNTS_BOX", str((os.cpu_count() or 2) + 1)))
                    jl = _pm2(["jlist"])
                    procs = json.loads(jl.stdout or "[]") if jl and jl.returncode == 0 else []
                    online = [x.get("name", "") for x in procs
                              if x.get("name", "").startswith("hunt-")
                              and x.get("name") not in ("hunt-bridge", "hunt-watchdog")
                              and (x.get("pm2_env", {}) or {}).get("status") == "online"]
                    if ("hunt-" + slug) not in online and len(online) >= cap:
                        return self._send(429, {
                            "error": f"box at capacity: {len(online)}/{cap} hunts already running on "
                                     f"{os.cpu_count()} core(s). Stop one first, or raise WATCHDOG_MAX_HUNTS_BOX "
                                     f"(a bigger box auto-allows more).",
                            "running": online, "cap": cap})
                except Exception:  # noqa: BLE001
                    pass
                if b.get("mock"):
                    log = os.path.join(os.path.expanduser(self.base), f"hunt-{slug}.log")
                    subprocess.Popen(["python3", os.path.join(ENGINE, "orchestrator.py"),
                                      "--scope", scope_path, "--hunt", "--mock"],
                                     stdout=open(log, "a"), stderr=subprocess.STDOUT,
                                     cwd=os.path.dirname(ENGINE), start_new_session=True)
                    return self._send(200, {"started": True, "program": prog, "mock": True, "runtime": "cursor-agent"})
                _pm2(["delete", "hunt-" + slug])                     # clear any stale instance
                r = _pm2(["start", HUNT_RUN_SH, "--name", "hunt-" + slug, "--", scope_path, interval])
                _pm2(["save"])
                if not r or r.returncode != 0:
                    return self._send(500, {"error": "pm2 start failed",
                                            "detail": (r.stderr[-200:] if r else "pm2 unavailable")})
                return self._send(200, {"started": True, "program": prog, "pm2": "hunt-" + slug,
                                        "runtime": "cursor-agent"})

            if p.path == "/hunt/stop":
                import targets as T
                slug = T._slug(b.get("program", ""))
                killed = _stop_target_sessions(slug)        # stop orchestrator + its agent sessions
                # session STATE is kept on stop -> a rerun RESUMES the same sessions (no new ones)
                return self._send(200, {"stopped": slug, "sessions_killed": killed, "state_kept": True})

            if p.path == "/auth/set":
                import authsession as AS
                r = AS.set_manual(b.get("program", ""), b.get("host", ""),
                                  cookie=b.get("cookie"), headers=b.get("headers"),
                                  token=b.get("token"), user=b.get("user"),
                                  ident=b.get("ident", "A"), base=self.base)
                return self._send(200 if r.get("ok") else 400, r)

            if p.path == "/auth/clear":
                import authsession as AS
                return self._send(200, AS.clear_manual(b.get("program", ""), base=self.base))

            if p.path == "/targets/ingest":
                text = b.get("text", "")
                if not text.strip():
                    return self._send(400, {"error": "provide 'text' (the pasted program page)"})
                import scopeparse as SP
                parsed = SP.parse(text, name=(b.get("program") or None))
                sc = SP.to_scope(parsed)
                if not sc["in_scope"]:
                    return self._send(400, {"error": "no in-scope hosts found — paste the full page incl. the Scopes section"})
                SP.register(sc, parsed, base=self.base)
                return self._send(200, {"added": sc["name"], "in_scope": len(sc["in_scope"]),
                                        "out_of_scope": len(sc["out_of_scope"]), "public": sc["public"],
                                        "user_agent": sc["user_agent"], "classes": sc["qualifying_classes"]})

            if p.path == "/targets/add":
                import targets as T
                prog = (b.get("program") or "").strip()
                if not prog:
                    return self._send(400, {"error": "program required"})
                scope = b.get("scope")
                if scope is None and b.get("hosts"):
                    scope = [h.strip() for h in b["hosts"].replace(",", " ").split() if h.strip()]
                if not scope:
                    return self._send(400, {"error": "provide 'scope' (json) or 'hosts' (space/comma/newline list)"})
                _, sc = T.add(prog, scope, base=self.base)
                return self._send(200, {"added": prog, "in_scope": len(sc.get("in_scope", [])),
                                        "monitor_apexes": sc.get("monitor_apexes", [])})

            if p.path == "/targets/remove":
                import targets as T
                import agent as AG
                import glob
                import shutil
                prog = b.get("program", "")
                slug = T._slug(prog)
                killed = _stop_target_sessions(slug)        # 1) stop its sessions
                # 2) purge this target's chat sessions (by the ids in its per-target state)
                ids, chats_removed = [], 0
                try:
                    ids = json.load(open(AG._pool_file(prog))).get("ids", [])
                except Exception:  # noqa: BLE001
                    ids = []
                for sid in ids:
                    for cdir in glob.glob(os.path.expanduser("~/.cursor/chats/*/" + str(sid))):
                        try:
                            shutil.rmtree(cdir)
                            chats_removed += 1
                        except OSError:
                            pass
                # 3) remove the per-target session directory, then 4) the scope itself
                try:
                    shutil.rmtree(AG._sess_dir(prog))
                except OSError:
                    pass
                removed = T.remove(prog, base=self.base)
                return self._send(200, {"removed": removed, "program": slug,
                                        "sessions_killed": killed, "chats_removed": chats_removed})

            return self._send(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return  # client (n8n/panel poller) hung up mid-response — benign, don't double-fault
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that doesn't dump a traceback every time a client resets the connection
    (a poller like n8n closing a socket mid-request is normal, not an error). Daemon threads so a
    restart/shutdown never hangs on an in-flight request."""
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128
    block_on_close = False

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return                          # expected: client hung up — stay quiet
        super().handle_error(request, client_address)


def main(argv=None):
    ap = argparse.ArgumentParser(description="host-side hunt-bridge")
    ap.add_argument("--host", default=os.environ.get("HUNT_BRIDGE_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("HUNT_BRIDGE_PORT", "8899")))
    ap.add_argument("--base", default=DEFAULT_BASE)
    a = ap.parse_args(argv)
    Handler.base = a.base
    try:                                            # a restart kills in-flight fix-chat threads — clear their
        import fixchat as _FC                        # orphaned '.busy' markers so chats aren't wedged on startup
        _n = _FC.clear_stale_busy(base=a.base)
        if _n:
            print(f"hunt-bridge: cleared {_n} orphaned fix-chat busy marker(s) from a prior restart", flush=True)
    except Exception:  # noqa: BLE001
        pass
    if not TOKEN:
        print("WARNING: HUNT_BRIDGE_TOKEN is empty — the bridge will refuse all authed requests "
              "until it is set.", file=sys.stderr)
    threading.Thread(target=_bg_loop, args=(a.base,), daemon=True).start()
    srv = _QuietThreadingHTTPServer((a.host, a.port), Handler)
    print(f"hunt-bridge {VERSION} listening on http://{a.host}:{a.port} (base={a.base})", flush=True)

    def _resume_later():
        time.sleep(1)
        try:
            import fixchat as _FC2
            _r = _FC2.resume_orphans(base=a.base)
            if _r:
                print(f"hunt-bridge: resumed {_r} fix-chat(s) cut off mid-turn", flush=True)
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=_resume_later, daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
