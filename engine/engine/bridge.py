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
import signal
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dedup as D        # noqa: E402
import novelty as N      # noqa: E402
import observe as O      # noqa: E402
import notify as NO      # noqa: E402

ENGINE = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.3"
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
TOKEN = os.environ.get("HUNT_BRIDGE_TOKEN", "")
MAX_BODY = int(os.environ.get("HUNT_BRIDGE_MAX_BODY", str(2 * 1024 * 1024)))   # 2 MB general request cap
VERIFY_MAX_BODY = int(os.environ.get("HUNT_VERIFY_MAX_BODY", str(32 * 1024 * 1024)))  # /verify accepts file uploads
_ACT_CACHE = {}   # /activity is polled ~every 8s and is CPU-heavy on big logs -> short-TTL cache


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
    """[{program, pid, running}] from pm2 — so hunts survive bridge restarts/crashes and stay tracked."""
    import json as _j
    r = _pm2(["jlist"])
    if not r or not r.stdout:
        return []
    try:
        procs = _j.loads(r.stdout)
    except Exception:
        return []
    out = []
    for pr in procs:
        name = pr.get("name", "")
        if name.startswith("hunt-") and name != "hunt-bridge":
            env = pr.get("pm2_env", {}) or {}
            out.append({"program": name[5:], "pid": pr.get("pid"),
                        "running": env.get("status") == "online", "restarts": env.get("restart_time", 0)})
    return out


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
                return self._send(200, {"hunts": _hunt_running(self.base)})
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
                        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
                        break
                return self._send(200, {"program": slug, "lines": lines[-n:]})
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
                import targets as T
                wd = os.environ.get("HUNT_WEB_DIR")
                nf = len([f for f in os.listdir(wd) if f.startswith("finding-") and f.endswith(".html")]) \
                    if wd and os.path.isdir(wd) else 0
                ap = os.path.join(os.path.expanduser(self.base), "_alerts", "feed.jsonl")
                na = sum(1 for _ in open(ap, errors="ignore")) if os.path.isfile(ap) else 0
                return self._send(200, {"targets": len(T.all_targets(self.base)),
                                        "running": len([h for h in _hunt_running(self.base) if h["running"]]),
                                        "findings": nf, "alerts": na})
            if p.path == "/activity":
                import re
                import glob as _glob
                q = parse_qs(p.query)
                try:
                    n = max(1, min(400, int((q.get("n", ["80"])[0]) or 80)))
                except (ValueError, TypeError):
                    n = 80
                prog = q.get("program", [""])[0]
                _ck = (prog, n); _tnow = datetime.now(timezone.utc).timestamp()
                _cc = _ACT_CACHE.get(_ck)
                if _cc and _tnow - _cc[0] < 15:
                    return self._send(200, _cc[1])
                if prog:
                    import targets as T
                    logs = [os.path.join(os.path.expanduser(self.base), T._slug(prog), "engine.log")]
                else:
                    logs = _glob.glob(os.path.join(os.path.expanduser(self.base), "*", "engine.log"))
                HUNT = re.compile(r"(\S+)\s+hunt: ([a-z0-9-]+)@(\S+) model=(\S+) skills=\[([^\]]*)\]")
                VAL = re.compile(r"(\S+)\s+validate: ([a-z0-9-]+)@(\S+) model=(\S+)")
                CONF = re.compile(r"(\S+)\s+validate: CONFIRMED (\S+) @ (\S+) \((\w+)\)")
                events, models = [], {}
                for lg in logs:
                    if not os.path.isfile(lg):
                        continue
                    pn = os.path.basename(os.path.dirname(lg))
                    try:                                  # tail only — recent events are at the end; keeps /activity fast as logs grow
                        with open(lg, "rb") as _fh:
                            _fh.seek(0, 2); _sz = _fh.tell(); _fh.seek(max(0, _sz - 131072))
                            _lines = _fh.read().decode("utf-8", "ignore").splitlines()
                    except OSError:
                        continue
                    for line in _lines:
                        m = HUNT.search(line)
                        if m:
                            ts, cls, url, model, sk = m.groups()
                            events.append({"ts": ts, "program": pn, "phase": "hunt", "class": cls, "url": url,
                                           "model": model, "skills": [s for s in sk.split(",") if s]})
                            models[model] = models.get(model, 0) + 1
                            continue
                        m = VAL.search(line)
                        if m:
                            ts, cls, url, model = m.groups()
                            events.append({"ts": ts, "program": pn, "phase": "validate", "class": cls,
                                           "url": url, "model": model, "skills": []})
                            models[model] = models.get(model, 0) + 1
                            continue
                        m = CONF.search(line)
                        if m:
                            ts, cls, url, sev = m.groups()
                            events.append({"ts": ts, "program": pn, "phase": "confirmed", "class": cls,
                                           "url": url, "model": "", "skills": [], "severity": sev})
                events.sort(key=lambda e: e["ts"], reverse=True)
                _payload = {"events": events[:n], "models": models}
                _ACT_CACHE[_ck] = (_tnow, _payload)
                return self._send(200, _payload)
            if p.path == "/capabilities":
                import sms as _SMS
                import learn as _L
                import guardrails as _G
                import sessions as _SESS
                _sinv = _SESS.inventory(self.base)
                # count chat sessions on disk (proves the pool keeps them low, not ballooning)
                chats = 0
                cbase = os.path.expanduser("~/.cursor/chats")
                try:
                    for ws in os.listdir(cbase):
                        wsp = os.path.join(cbase, ws)
                        if os.path.isdir(wsp):
                            chats += sum(1 for c in os.listdir(wsp) if os.path.isdir(os.path.join(wsp, c)))
                except OSError:
                    pass
                return self._send(200, {
                    "sessions": {"chats_on_disk": chats,
                                 "orphaned_chats": len(_sinv["orphans"]),
                                 "pool_per_target": int(os.environ.get("HUNT_SESSION_POOL", "3")),
                                 "max_uses": int(os.environ.get("HUNT_SESSION_MAX_USES", "25"))},
                    "websearch": {"ready": True, "provider": "duckduckgo-html"},
                    "identity": {"ready": True, "provider": "mail.tm", "max_accounts": _G.max_accounts()},
                    "sms": _SMS.status(),
                    "learn": {"learned_skills": len(_L.learned_index()),
                              "gaps": len(_L.gaps(self.base)), "journal": len(_L.journal(self.base))},
                    "guardrails": {"no_bruteforce": True, "scope_enforced": True,
                                   "max_accounts_per_program": _G.max_accounts()}})
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
            return self._send(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return  # client (n8n/panel poller) hung up mid-response — benign, don't double-fault
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        if not self._authed():
            return
        p = urlparse(self.path)
        cap = VERIFY_MAX_BODY if p.path == "/verify" else MAX_BODY
        clen = int(self.headers.get("Content-Length") or 0)
        if clen > cap:
            return self._send(413, {"error": f"body too large (> {cap} bytes)"})
        b = self._body(cap)
        try:
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
                res = V.verify_finding(f, program=prog, base=self.base)
                res["extracted"] = {k: parsed[k] for k in ("vuln_class", "severity", "url", "title") if parsed.get(k)}
                if intake:
                    res["uploads"] = {"saved": [s["name"] for s in intake["saved"]],
                                      "rejected": intake["rejected"], "images": intake["images"]}
                if b.get("deep"):
                    op = V.deep_opinion(f, res, program=prog, base=self.base)
                    res["triager_opinion"] = op
                    res["verdict"] = V.combine_verdict(res, op)      # trigger = stricter of gate + expert
                    res["accept"] = res["verdict"] == "READY"
                return self._send(200, res)

            if p.path == "/sessions/clear":
                import sessions as _SESS
                r = _SESS.clear_orphans(self.base, confirm=bool(b.get("confirm")))
                return self._send(200, r)

            if p.path == "/sessions/reset":
                import sessions as _SESS
                r = _SESS.reset_target(b.get("program", ""), self.base, confirm=bool(b.get("confirm")))
                code = 200 if not r.get("error") else 400
                return self._send(code, r)

            if p.path == "/notify":
                ok = NO.send_safe(b.get("subject", "(no subject)"), b.get("body", ""),
                                  to=b.get("to"), cc=b.get("cc"), html=b.get("html"))
                return self._send(200, {"sent": ok, "configured": NO.configured()})

            if p.path == "/hunt":
                # n8n / the panel trigger a Cursor-agent hunt. Real hunts run under pm2 so they survive
                # bridge restarts + auto-restart on crash; mock runs inline for testing.
                import targets as T
                import subprocess
                prog = b.get("program", "")
                sc = T.load(prog, base=self.base)
                if not sc:
                    return self._send(404, {"error": f"unknown program: {prog} (add it first)"})
                slug = T._slug(prog)
                scope_path = os.path.join(os.path.expanduser(self.base), "_targets", slug + ".json")
                interval = str(int(b.get("interval", 1800)))
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
    if not TOKEN:
        print("WARNING: HUNT_BRIDGE_TOKEN is empty — the bridge will refuse all authed requests "
              "until it is set.", file=sys.stderr)
    srv = _QuietThreadingHTTPServer((a.host, a.port), Handler)
    print(f"hunt-bridge {VERSION} listening on http://{a.host}:{a.port} (base={a.base})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
