#!/usr/bin/env python3
"""
fixchat.py — interactive "fix my report" chat for the Verify tab.

Flow: the operator uploads a report + evidence, the verify gate says what's missing, then they open a
fix chat: a Cursor agent session that can READ and EDIT the uploaded files (in an isolated work dir)
to fix the failed checks — add steps, tighten the PoC section, fix severity, redact PII. The operator
chats, watches the files change, downloads the fixed files, then CLOSES the chat: the work dir and
the agent session are removed (same verify-only hygiene as /verify).

Safety:
  - work dir lives under <base>/<slug>/verify-fixchat/<chat_id>/ — chat_id is a uuid4, path-safe.
  - file saves reuse verify's hardening (basename-only, extension allow-list, size caps, chmod 600).
  - downloads are basename-only and must resolve INSIDE the chat's dir.
  - the agent is instructed to edit ONLY files in the work dir.
  - close() removes the dir AND the cursor-agent session (sessions.drop_ids, pool-protected).

CLI: python3 fixchat.py selftest
"""
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
MSG_TIMEOUT = int(os.environ.get("HUNT_FIXCHAT_TIMEOUT", "2400"))  # active repro (accounts + re-test + rewrite) needs time
CONTINUE_TIMEOUT = int(os.environ.get("HUNT_FIXCHAT_CONTINUE", str(MSG_TIMEOUT)))
BUSY_GRACE = MSG_TIMEOUT + CONTINUE_TIMEOUT + 180

# Never log these engine errors as the 0x avatar text — they rendered as a dead "timeout" bubble.
_DEAD_AGENT = {"timeout", "rate-limited", "agent-error", "(no reply)"}
_TIMEOUT_CONTINUE = (
    "You were cut off because the previous turn hit the time budget. "
    "Do NOT restart from scratch. Continue the LAST operator request using files already in this directory. "
    "Honor every constraint the operator already gave. Finish the in-progress work and reply with a short "
    "summary of what is now in the files."
)
_REWRITE_FIRST = (
    "FIRST reply this turn: save the rewritten report file(s) in this directory. "
    "Do not start a long live-account reproduction until those files exist. "
    "Title must say unauthenticated (not authenticated user). Summary, steps, impact, and remediation "
    "must be distinct sections; remediation must not be empty. Do not quote third-party comment bodies "
    "or emails. Mention public docs only as 'this is systemic'. If an own-doc unique-marker PoC cannot "
    "be captured in a few minutes, leave TODO(operator) lines for it. STOP at draft. Then reply with a "
    "short summary of what is now in the files.\n\n"
)
_TIMEOUT_USER = (
    "The last turn ran past the time budget and was stopped so this panel stays live. "
    "This chat is still open and the files on disk were kept. Send continue and I will resume the same session."
)
_RATELIMIT_USER = (
    "The agent hit a rate limit. This chat is still open — wait a minute and send again; it will resume the same session."
)
_EMPTY_USER = (
    "The last turn ended without a reply. This chat is still open — send continue and I will resume the same session."
)


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "adhoc"


def _chat_id_ok(cid):
    return bool(re.fullmatch(r"[a-f0-9-]{36}", str(cid or "")))


def _dir(base, program, cid):
    return os.path.realpath(os.path.join(os.path.expanduser(base), _slug(program),
                                         "verify-fixchat", cid))


def _meta_path(root):
    return os.path.join(root, ".fixchat.json")


def _log_path(root):
    return os.path.join(root, ".fixchat-log.json")


_LOG_LOCK = threading.Lock()


def _update_log(root, update):
    if not os.path.isdir(root):
        return []
    with _LOG_LOCK:
        try:
            log = json.load(open(_log_path(root)))
        except Exception:  # noqa: BLE001
            log = []
        log = update(log) or log
        try:
            json.dump(log[-200:], open(_log_path(root), "w"))
            os.chmod(_log_path(root), 0o600)
        except OSError:
            pass
        return log


def _append_log(root, role, text):
    def append(log):
        log.append({"role": role, "text": str(text or "")[:12000], "ts": time.time()})
        return log
    return _update_log(root, append)


def _load_meta(root):
    try:
        return json.load(open(_meta_path(root)))
    except Exception:  # noqa: BLE001
        return None


def _save_meta(root, meta):
    try:
        json.dump(meta, open(_meta_path(root), "w"))
        os.chmod(_meta_path(root), 0o600)
    except OSError:
        pass


def _save_session(root, meta, r):
    if r.get("session_id"):
        meta["session_id"] = r["session_id"]
        if r.get("model"):
            meta["model"] = r["model"]
        _save_meta(root, meta)


def _busy_path(root):
    return os.path.join(root, ".busy")


def _touch_busy(root):
    try:
        json.dump({"ts": time.time(), "cid": os.path.basename(root)}, open(_busy_path(root), "w"))
    except OSError:
        pass


def _busy_age(root):
    bp = _busy_path(root)
    if not os.path.isfile(bp):
        return None
    try:
        raw = open(bp).read().strip()
        if raw.startswith("{"):
            return max(0.0, time.time() - float((json.loads(raw) or {}).get("ts") or 0))
        return max(0.0, time.time() - float(raw or 0))
    except Exception:  # noqa: BLE001
        return 0.0


def _agent_alive(root):
    """True when a cursor-agent process is actually running this chat (uuid in argv)."""
    cid = os.path.basename(root)
    if not _chat_id_ok(cid):
        return False
    try:
        out = subprocess.run(["pgrep", "-af", "cursor-agent"], capture_output=True, text=True, timeout=5)
    except Exception:  # noqa: BLE001
        return False
    for ln in (out.stdout or "").splitlines():
        if cid in ln and "pgrep" not in ln:
            return True
    return False


def _same_you(root, text):
    try:
        log = json.load(open(_log_path(root)))
    except Exception:  # noqa: BLE001
        return False
    last = next((m for m in reversed(log or []) if m.get("role") == "you"), None)
    if not last:
        return False
    a = re.sub(r"\s+", " ", str(last.get("text") or "")).strip()
    b = re.sub(r"\s+", " ", str(text or "")).strip()
    return bool(a) and a[:4000] == b[:4000]


def _pending_path(root):
    return os.path.join(root, ".pending")


def _save_pending(root, text):
    try:
        json.dump({"text": str(text or "")[:8000], "ts": time.time()}, open(_pending_path(root), "w"))
    except OSError:
        pass


def _take_pending(root):
    pp = _pending_path(root)
    try:
        rec = json.load(open(pp))
        os.remove(pp)
        return str(rec.get("text") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


_HB_PREFIX = "agent is still working (may edit files)"


def _heartbeat_log(root, started):
    elapsed = int(time.time() - started)
    line = f"{_HB_PREFIX}… {elapsed}s. Do not resend — this chat is live."
    def heartbeat(log):
        if log and log[-1].get("role") == "system" and str(log[-1].get("text") or "").startswith(_HB_PREFIX):
            log[-1] = {"role": "system", "text": line, "ts": time.time()}
        else:
            log.append({"role": "system", "text": line, "ts": time.time()})
        return log
    return _update_log(root, heartbeat)


def _clear_busy(root):
    try:
        os.remove(_busy_path(root))
    except OSError:
        pass


def _agent_bubble(r):
    """Never surface a raw engine error (timeout / rate-limited) as the 0x avatar text."""
    text = (r.get("result") or "").strip()
    err = (r.get("error") or "").strip()
    if text and err != "timeout":
        return "agent", text[:12000]
    if text:
        return "agent", text[:12000]
    if err == "timeout":
        return "system", _TIMEOUT_USER
    if err == "rate-limited":
        return "system", _RATELIMIT_USER
    if err:
        return "system", f"Agent error ({err}). This chat is still open — send again to resume."
    low = text.lower()
    if "connection lost" in low or "reconnect" in low:
        return "system", ("Cursor dropped the connection. This chat is still open — "
                          "the next send resumes the same files. Do not resend while the heartbeat is live.")
    return "system", _EMPTY_USER


def _rewrite_dead_logs(root, log):
    """Heal already-written 'timeout' 0x bubbles (legacy chats) into a recoverable system line."""
    changed = False
    for m in log or []:
        if m.get("role") != "agent":
            continue
        t = str(m.get("text") or "").strip()
        low = t.lower()
        if low not in _DEAD_AGENT:
            continue
        m["role"] = "system"
        if low == "timeout":
            m["text"] = _TIMEOUT_USER
        elif low == "rate-limited":
            m["text"] = _RATELIMIT_USER
        else:
            m["text"] = _EMPTY_USER
        changed = True
    if changed:
        def rewrite(current):
            by_ts = {m.get("ts"): i for i, m in enumerate(current)}
            for old in log:
                ts = old.get("ts")
                if ts in by_ts:
                    current[by_ts[ts]].update(old)
                else:
                    current.append(old)
            return current
        log = _update_log(root, rewrite)
    return log


def _run_turn(root, task, meta, timeout):
    import agent as A
    r = A.run_agent(task, context=None, resume_id=meta.get("session_id"),
                    model=meta.get("model"), timeout=timeout, attempts=1)
    _save_session(root, meta, r)
    return r


def _run_turn_recover(root, task, meta, timeout):
    """One agent turn; on timeout with a live session_id, auto-continue once instead of dying."""
    r = _run_turn(root, task, meta, timeout)
    if (r.get("error") or "") != "timeout":
        return r
    sid = r.get("session_id") or meta.get("session_id")
    if not sid:
        return r
    meta["session_id"] = sid
    _touch_busy(root)
    r2 = _run_turn(root, _TIMEOUT_CONTINUE, meta, min(timeout, CONTINUE_TIMEOUT) or timeout)
    if not r2.get("error") and (r2.get("result") or "").strip():
        return r2
    return r2 if r2.get("error") != "timeout" else r


def _save_files(files, root):
    """Save uploads into the chat work dir with the same hardening as verify.ingest_files."""
    import verify as V
    saved, rejected, total = [], [], 0
    os.makedirs(root, exist_ok=True)
    for f in (files or [])[:40]:
        raw_name = os.path.basename(str(f.get("name") or "").replace("\x00", "")).strip()
        name = V._safe_name(f.get("name"))
        ext = os.path.splitext(name)[1].lower()
        if raw_name.startswith(".") or name == "fixchat.json":   # never shadow the chat meta file
            rejected.append({"name": name, "reason": "hidden/meta names not allowed"}); continue
        try:
            import base64
            raw = base64.b64decode((f.get("b64") or "").encode(), validate=False)
        except Exception:  # noqa: BLE001
            rejected.append({"name": name, "reason": "invalid base64"}); continue
        if len(raw) > MAX_FILE:
            rejected.append({"name": name, "reason": "too large"}); continue
        if total + len(raw) > MAX_TOTAL:
            rejected.append({"name": name, "reason": "total cap exceeded"}); break
        if ext not in V.ALLOWED_TEXT and ext not in V.ALLOWED_BIN:
            rejected.append({"name": name, "reason": f"type '{ext or '?'}' not allowed"}); continue
        path = os.path.realpath(os.path.join(root, name))
        if not path.startswith(root + os.sep):
            rejected.append({"name": name, "reason": "path escape blocked"}); continue
        with open(path, "wb") as fh:
            fh.write(raw)
        os.chmod(path, 0o600)
        total += len(raw)
        saved.append(name)
    return saved, rejected


def _listing(root):
    out = []
    try:
        for n in sorted(os.listdir(root)):
            p = os.path.join(root, n)
            if os.path.isfile(p) and not n.startswith("."):
                out.append({"name": n, "bytes": os.path.getsize(p), "mtime": os.path.getmtime(p)})
    except OSError:
        pass
    return out


def _task_start(root, finding, verify_res):
    fails = [c for c in (verify_res or {}).get("checks", []) if not c.get("pass")]
    fixes = "\n".join(f"- {c['check']}: {c.get('fix') or c.get('note', '')}" for c in fails) \
        or "- (no failed checks — polish the report for clarity and triager-readiness)"
    eng = os.path.dirname(os.path.abspath(__file__))
    program = (finding or {}).get("program") or ""
    intrusive = os.environ.get("HUNT_INTRUSIVE") == "1"
    repro = ""
    if program and intrusive:
        try:
            import targets as _T
            sc = _T.load(program) or {}
        except Exception:  # noqa: BLE001
            sc = {}
        in_scope = sc.get("in_scope", []) if isinstance(sc, dict) else []
        ua = sc.get("user_agent") if isinstance(sc, dict) else None
        scope_line = (f"IN-SCOPE hosts ONLY: {', '.join(in_scope[:30])}." if in_scope else
                      f"Scope not pre-loaded — web-search this program's official bug-bounty scope ('{program}') and "
                      "only hit hosts you confirm in-scope.")
        repro = (
            "\n\nACTIVELY REPRODUCE + CAPTURE REAL EVIDENCE (authorized active testing): don't just add "
            "'TODO(operator)' lines — actually PROVE the bug and paste the captured proof into the report. "
            + scope_line + (f" Send every request with User-Agent: '{ua}'." if ua else "") +
            " You MAY create test accounts and perform state-changing actions to demonstrate impact. HARD "
            "LIMITS: in-scope only, NO brute-force, NO destructive/DoS/mass-exploitation (prove it ONCE then STOP). "
            "Tools:\n"
            f"  - mint a test account: `python3 {eng}/identity.py new --program {program}` "
            f"(read its mail: `python3 {eng}/identity.py poll --program {program} --email <addr>`).\n"
            f"  - fetch with the stored login (bypasses edge gating): `python3 {eng}/netget.py GET \"<url>\" --as A` "
            f"(POST: `... POST \"<url>\" '<body>' --as A`; second account: `--as B`).\n"
            f"  - cross-account IDOR/BOLA sweep: `python3 {eng}/authz.py diff --slug {program} --url \"<A-owned url>\"`.\n"
            "If you reproduce it, paste the REAL request+response into the report's PoC section (redact secrets) and "
            "set an honest severity. If you CANNOT reproduce, say so plainly and keep a TODO(operator) line — never fabricate.")
    return (
        "You are a bug-bounty REPORT FIXER" + (" + REPRODUCER" if repro else "") + ". The operator's draft report "
        f"failed the verification gate. The uploaded report + evidence files are in: {root} — READ and EDIT files "
        "in THIS directory (write files here only). Your job: fix the report so it passes — rewrite/add sections "
        "IN the report file(s): clear numbered repro steps, a PoC section with the raw request/response, a concrete "
        "impact statement, honest severity. Never invent evidence — if proof is missing and you can't reproduce it, "
        "add a clearly-marked 'TODO(operator):' line saying exactly what to capture. Redact any real PII/secrets."
        + repro +
        f"\n\nVERIFY VERDICT: {(verify_res or {}).get('verdict', '?')}\n"
        f"FAILED CHECKS + WHAT TO ADD:\n{fixes}\n\n"
        f"FINDING CONTEXT:\n{json.dumps({k: v for k, v in (finding or {}).items() if not k.startswith('_')}, indent=2)[:4000]}\n\n"
        "Start by reading the report file(s), then make the fixes (reproduce first if authorized). Reply with a "
        "short summary of what you changed, whether you REPRODUCED it (real_bug: yes/no/inconclusive), and what the "
        "operator still needs.")


def _find_root(cid, base=DEFAULT_BASE):
    """Locate a chat's work dir by id (uuid4, path-safe). None if closed/expired/invalid."""
    import glob
    if not _chat_id_ok(cid):
        return None
    hits = glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", cid))
    root = os.path.realpath(hits[0]) if hits else None
    return root if root and os.path.isdir(root) else None


def status(cid, base=DEFAULT_BASE):
    """Chat state for a panel refresh: meta + file listing + the conversation log."""
    root = _find_root(cid, base)
    if not root:
        return {"error": "chat not found (closed or expired)"}
    meta = _load_meta(root) or {}
    try:
        log = json.load(open(_log_path(root)))
    except Exception:  # noqa: BLE001
        log = []
    log = _rewrite_dead_logs(root, log)
    return {"chat_id": cid, "program": meta.get("program"), "created": meta.get("created"),
            "verdict": meta.get("verdict"), "files": _listing(root), "log": log, "open": True,
            "busy": os.path.exists(_busy_path(root))}


def list_chats(base=DEFAULT_BASE):
    """All OPEN fix chats across programs — the panel sidebar. Newest first."""
    import glob
    out = []
    for d in glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", "*")):
        if not os.path.isdir(d):
            continue
        cid = os.path.basename(d)
        if not _chat_id_ok(cid):
            continue
        meta = _load_meta(d) or {}
        prog = meta.get("program") or os.path.basename(os.path.dirname(os.path.dirname(d)))
        out.append({"chat_id": cid, "program": prog,
                    "created": meta.get("created") or os.path.getmtime(d),
                    "verdict": meta.get("verdict"), "files": len(_listing(d))})
    out.sort(key=lambda x: -(x["created"] or 0))
    return {"chats": out}


def _open_dir(program, files, verify_res, base, model, chat_id):
    """Create the work dir + meta. Shared by start() (sync, selftest) and start_async() (HTTP)."""
    cid = chat_id if _chat_id_ok(chat_id) else str(uuid.uuid4())
    root = _dir(base, program, cid)
    os.makedirs(root, exist_ok=True)
    os.chmod(root, 0o700)
    saved, rejected = _save_files(files, root)
    meta = {"chat_id": cid, "program": _slug(program), "session_id": None,
            "model": model, "created": time.time(),
            "verdict": (verify_res or {}).get("verdict")}
    _save_meta(root, meta)
    return cid, root, meta, saved, rejected


def _finish_turn(root, r):
    role, text = _agent_bubble(r)
    if os.path.isdir(root):
        _append_log(root, role, text)
    return role, text


def start(program, finding, files, verify_res, base=DEFAULT_BASE, model=None, chat_id=None):
    """Open a fix chat (synchronous — used by selftest / CLI). HTTP uses start_async so :8899 stays live."""
    cid, root, meta, saved, rejected = _open_dir(program, files, verify_res, base, model, chat_id)
    r = _run_turn_recover(root, _task_start(root, finding, verify_res), meta, MSG_TIMEOUT)
    if not os.path.isdir(root):
        return {"chat_id": cid, "reply": "", "error": "chat was closed while opening",
                "files": [], "saved": saved, "rejected": rejected, "closed_mid_open": True}
    role, text = _finish_turn(root, r)
    return {"chat_id": cid, "reply": text, "error": None if role == "agent" else r.get("error"),
            "files": _listing(root), "saved": saved, "rejected": rejected}


def start_async(program, finding, files, verify_res, base=DEFAULT_BASE, model=None, chat_id=None):
    """Open a fix chat without holding the HTTP request (nginx /panel/api/verify times out at 650s;
    a first-turn agent run can take MSG_TIMEOUT). Panel polls status() until busy clears."""
    cid, root, meta, saved, rejected = _open_dir(program, files, verify_res, base, model, chat_id)
    task = _task_start(root, finding, verify_res)
    _touch_busy(root)

    def _run():
        try:
            m = _load_meta(root) or meta
            r = _run_turn_recover(root, task, m, MSG_TIMEOUT)
            _finish_turn(root, r)
        except Exception as e:  # noqa: BLE001
            if os.path.isdir(root):
                _append_log(root, "system",
                            f"Agent error ({type(e).__name__}: {e}). This chat is still open — send again.")
        finally:
            _clear_busy(root)

    threading.Thread(target=_run, daemon=True).start()
    return {"chat_id": cid, "queued": True, "busy": True, "reply": "",
            "files": _listing(root), "saved": saved, "rejected": rejected}


def message(cid, text, base=DEFAULT_BASE, program=None):
    """Send a follow-up: resumes the SAME agent session so it remembers the report + prior edits."""
    root = _find_root(cid, base)
    if not root:
        return {"error": "chat not found (closed or expired)"}
    meta = _load_meta(root) or {}
    _append_log(root, "you", text)
    task = (str(text or "")[:8000] +
            f"\n\n(Reminder: the files are in {root} — edit them in place, this directory only. "
            "Reply with a short summary of changes.)")
    r = _run_turn_recover(root, task, meta, MSG_TIMEOUT)
    if not os.path.isdir(root):
        return {"reply": "", "error": "chat was closed", "files": [], "closed_mid_run": True}
    role, text_out = _finish_turn(root, r)
    return {"reply": text_out, "error": None if role == "agent" else r.get("error"),
            "files": _listing(root)}


def clear_stale_busy(base=DEFAULT_BASE):
    """Remove ALL fix-chat '.busy' markers. Called on bridge startup: a fresh process has NO running message
    threads, so every existing marker is orphaned (its background thread died with the previous process) and
    would otherwise wedge the chat ('agent is still working') for up to MSG_TIMEOUT. Returns the count cleared."""
    import glob
    n = 0
    for bp in glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", "*", ".busy")):
        try:
            os.remove(bp)
            n += 1
        except OSError:
            pass
    return n


def _follow_task(root, text, rewrite_first=False):
    body = str(text or "")[:8000]
    prefix = _REWRITE_FIRST if rewrite_first else ""
    return (prefix + body +
            f"\n\n(Reminder: the files are in {root} — edit them in place, this directory only. "
            "Honor CONSTRAINTS.md if it exists. Reply with a short summary of changes.)")


def _spawn_turn(root, task):
    """Run one agent turn in a daemon thread. HTTP handlers must return before this starts working."""
    started = time.time()
    _touch_busy(root)
    stop = threading.Event()

    def _beat():
        last_hb = 0
        while not stop.wait(15):
            if not os.path.isdir(root):
                return
            _touch_busy(root)
            now = time.time()
            if now - last_hb >= 45:
                _heartbeat_log(root, started)
                last_hb = now

    def _run():
        try:
            meta = _load_meta(root) or {}
            r = _run_turn_recover(root, task, meta, MSG_TIMEOUT)
            _finish_turn(root, r)
        except Exception as e:  # noqa: BLE001
            if os.path.isdir(root):
                _append_log(root, "system",
                            f"Agent error ({type(e).__name__}: {e}). This chat is still open — send again.")
        finally:
            stop.set()
            _clear_busy(root)
            nxt = _take_pending(root)
            if nxt and os.path.isdir(root):
                _append_log(root, "you", nxt)
                _spawn_turn(root, _follow_task(root, nxt, rewrite_first=True))

    threading.Thread(target=_beat, daemon=True).start()
    threading.Thread(target=_run, daemon=True).start()


def message_async(cid, text, base=DEFAULT_BASE):
    """Queue a follow-up and run the agent in the BACKGROUND. Agent edits (esp. active reproduction — making
    accounts, re-running the PoC) take minutes, so we must NOT hold the HTTP request open past a proxy/client
    timeout (the cause of 'error: timeout'). The panel polls status() until 'busy' clears. Returns at once."""
    root = _find_root(cid, base)
    if not root:
        return {"error": "chat not found (closed or expired)"}
    age = _busy_age(root)
    alive = _agent_alive(root)
    if age is not None and (alive or age < 120):
        if _same_you(root, text):
            return {"queued": True, "busy": True, "already": True, "chat_id": cid}
        _save_pending(root, text)
        return {"queued": True, "busy": True, "pending": True, "chat_id": cid}
    if age is not None and not alive:
        _clear_busy(root)
    _append_log(root, "you", str(text or "")[:8000])
    _spawn_turn(root, _follow_task(root, text, rewrite_first=True))
    return {"queued": True, "busy": True, "chat_id": cid}


def resume_orphans(base=DEFAULT_BASE):
    """Re-queue chats whose last operator turn never got a reply (busy marker gone, last you/cutoff)."""
    import glob
    n = 0
    for d in glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", "*")):
        if not os.path.isdir(d) or not _chat_id_ok(os.path.basename(d)):
            continue
        if os.path.exists(_busy_path(d)) and (_agent_alive(d) or (_busy_age(d) or 0) < 120):
            continue
        if os.path.exists(_busy_path(d)) and not _agent_alive(d):
            _clear_busy(d)
        try:
            log = json.load(open(_log_path(d)))
        except Exception:  # noqa: BLE001
            continue
        last = log[-1] if log else {}
        role = last.get("role")
        txt = str(last.get("text") or "")
        you = next((str(m.get("text") or "") for m in reversed(log or []) if m.get("role") == "you"), "")
        cutoff = role == "system" and any(k in txt.lower() for k in
                                          ("cut off", "time budget", "still working", "gateway timeout"))
        if not you.strip():
            continue
        if role not in ("you", "system") or (role == "system" and not cutoff):
            continue
        if role == "agent":
            continue
        _append_log(d, "system",
                    "Previous turn was cut off (gateway timeout or bridge restart). Resuming the last message.")
        _spawn_turn(d, _follow_task(d, you, rewrite_first=True))
        n += 1
    return n


def read_file(cid, name, base=DEFAULT_BASE):
    """Bytes of one file in the chat dir (download). Basename-only, must resolve inside the dir."""
    import verify as V
    root = _find_root(cid, base)
    if not root:
        return None, None
    safe = V._safe_name(name)
    if safe.startswith("."):
        return None, None
    path = os.path.realpath(os.path.join(root, safe))
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        return None, None
    with open(path, "rb") as fh:
        return safe, fh.read()


def close(cid, base=DEFAULT_BASE):
    """Close the chat: remove the work dir AND the agent session (verify-only hygiene)."""
    import shutil
    root = _find_root(cid, base)
    if not root:
        return {"closed": False, "error": "chat not found"}
    meta = _load_meta(root) or {}
    try:
        shutil.rmtree(root)
    except OSError:
        pass
    removed = 0
    sid = meta.get("session_id")
    if sid:
        try:
            import sessions as SESS
            removed = SESS.drop_ids([sid]).get("removed", 0)
        except Exception:  # noqa: BLE001
            pass
    return {"closed": True, "dir_removed": not os.path.isdir(root), "session_dirs_removed": removed}


def _selftest():
    import base64 as _b64
    import tempfile
    base = tempfile.mkdtemp()
    os.environ["HUNT_MOCK_AGENT"] = "1"
    os.environ["HUNT_MOCK_RESULT"] = "fixed the report"
    try:
        files = [{"name": "report.md", "b64": _b64.b64encode(b"# draft").decode()},
                 {"name": "../evil.sh", "b64": _b64.b64encode(b"echo hi").decode()},
                 {"name": ".fixchat.json", "b64": _b64.b64encode(b"{}").decode()}]
        r = start("acme", {"vuln_class": "idor", "url": "https://x"}, files,
                  {"verdict": "NEEDS_FIXES", "checks": [{"check": "has PoC / evidence", "pass": False,
                                                         "fix": "attach raw request/response"}]}, base=base)
        cid = r["chat_id"]
        assert _chat_id_ok(cid) and "report.md" in r["saved"], r
        assert "evil.sh" in r["saved"], r                        # traversal collapsed to basename
        assert all(x["name"] != ".fixchat.json" for x in r["files"]), "meta must be protected"
        assert any(x["reason"] == "hidden/meta names not allowed" for x in r["rejected"]), r
        m = message(cid, "tighten the impact section", base=base)
        assert m.get("reply") and not m.get("error"), m
        name, data = read_file(cid, "report.md", base=base)
        assert name == "report.md" and data == b"# draft", (name, data)
        assert read_file(cid, "../../etc/passwd", base=base) == (None, None)
        assert read_file(cid, ".fixchat.json", base=base) == (None, None)

        role, text = _agent_bubble({"result": "", "error": "timeout"})
        assert role == "system" and text.strip().lower() != "timeout" and "time budget" in text.lower(), text
        role, text = _agent_bubble({"result": "fixed", "error": None})
        assert role == "agent" and text == "fixed", (role, text)

        root = _find_root(cid, base)
        _append_log(root, "agent", "timeout")
        s = status(cid, base=base)
        assert not any(x.get("role") == "agent" and str(x.get("text") or "").strip().lower() == "timeout"
                       for x in s["log"]), s["log"][-3:]
        assert any("time budget" in (x.get("text") or "") for x in s["log"]), s["log"][-3:]

        os.environ["HUNT_MOCK_ERROR"] = "timeout"
        os.environ["HUNT_MOCK_RESULT"] = ""
        q = message_async(cid, "keep going", base=base)
        assert q.get("queued"), q
        for _ in range(80):
            s = status(cid, base=base)
            if not s.get("busy"):
                break
            time.sleep(0.05)
        assert not s.get("busy"), s
        assert not any(x.get("role") == "agent" and str(x.get("text") or "").strip().lower() == "timeout"
                       for x in s["log"]), s["log"][-4:]
        os.environ.pop("HUNT_MOCK_ERROR", None)
        os.environ["HUNT_MOCK_RESULT"] = "fixed the report"

        r2 = start_async("acme", {"vuln_class": "idor", "url": "https://x"}, files,
                         {"verdict": "NEEDS_FIXES", "checks": []}, base=base)
        assert r2.get("queued") and r2.get("busy") and r2.get("chat_id") and r2["chat_id"] != cid, r2
        for _ in range(80):
            s2 = status(r2["chat_id"], base=base)
            if not s2.get("busy"):
                break
            time.sleep(0.05)
        assert not s2.get("busy"), s2

        orphan = start("acme", {"vuln_class": "idor", "url": "https://x"},
                       [{"name": "report.md", "b64": _b64.b64encode(b"# d").decode()}],
                       {"verdict": "NEEDS_FIXES", "checks": []}, base=base)
        ocid = orphan["chat_id"]
        oroot = _find_root(ocid, base)
        _append_log(oroot, "you", "same ping")
        _touch_busy(oroot)
        qsame = message_async(ocid, "same ping", base=base)
        assert qsame.get("already"), qsame
        qpend = message_async(ocid, "a different follow-up", base=base)
        assert qpend.get("pending"), qpend
        _append_log(oroot, "you", "finish the impact section")
        _clear_busy(oroot)
        assert resume_orphans(base=base) >= 1
        for _ in range(80):
            so = status(ocid, base=base)
            if not so.get("busy"):
                break
            time.sleep(0.05)
        assert not so.get("busy"), so
        assert any(x.get("role") == "agent" for x in (so.get("log") or [])), so.get("log")
        close(ocid, base=base)

        c = close(cid, base=base)
        assert c["closed"] and c["dir_removed"], c
        assert message(cid, "hi", base=base).get("error"), "closed chat must be gone"
        assert close("not-a-uuid", base=base).get("error")
        close(r2["chat_id"], base=base)
    finally:
        os.environ.pop("HUNT_MOCK_AGENT", None)
        os.environ.pop("HUNT_MOCK_RESULT", None)
        os.environ.pop("HUNT_MOCK_ERROR", None)
    print("fixchat.py self-test: PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(_selftest())
    print(__doc__)
