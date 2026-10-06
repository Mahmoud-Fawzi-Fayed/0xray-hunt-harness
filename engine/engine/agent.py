#!/usr/bin/env python3
"""
agent.py — the engine's LLM dispatch, running on CURSOR agents (not claude).

The actual hunting/validation is driven by the `cursor-agent` CLI in headless mode
(`cursor-agent -p ... --output-format json -f`), which is logged in on this box. Everything else
in the engine (scope, state, orchestration, dedup, novelty) is deterministic code. Swapping to Cursor
means the whole harness — in-chat, headless, pm2, and n8n-triggered — uses one runtime with no
separate claude login.

Agents are asked to end with a fenced ```json``` block which we parse into structured data.

Model: left to Cursor's default unless CURSOR_HUNT_MODEL is set (e.g. "sonnet-4-thinking", "gpt-5").
"""
import json
import os
import re
import signal
import subprocess
import threading
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
CURSOR_BIN = os.environ.get("CURSOR_AGENT_BIN", "cursor-agent")

# Model policy: hunt ONLY on this approved pool, rotating per call for diversity (and to dodge a single
# model's safety-filter stalls). Configured via CURSOR_HUNT_MODELS (comma list) in harness/.env.
_RR = {"i": 0}


def _pick_model():
    try:
        import notify
        notify._load_env_file()                 # make CURSOR_HUNT_MODELS* available regardless of caller
    except Exception:
        pass
    pool = [m.strip() for m in os.environ.get("CURSOR_HUNT_MODELS", "").split(",") if m.strip()]
    if pool:
        m = pool[_RR["i"] % len(pool)]
        _RR["i"] += 1
        return m
    return os.environ.get("CURSOR_HUNT_MODEL") or None


def _parse_result_json(stdout):
    """cursor-agent --output-format json prints one result object; be tolerant of leading warnings."""
    stdout = (stdout or "").strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass
    for m in reversed(re.findall(r"\{.*\}", stdout, re.S)):   # last brace-balanced-ish blob
        try:
            return json.loads(m)
        except json.JSONDecodeError:
            continue
    return None


# transient errors worth one quick retry (a cursor-agent hiccup / non-JSON blip / momentary limit).
# NOTE: 'timeout' is deliberately NOT here — retrying a timed-out step would burn another full timeout;
# instead the step is left un-tested (hunt() doesn't mark it) so the NEXT round retries it cheaply.
_RETRYABLE = {"parse:no-json", "rate-limited"}


def _run_once(cmd, m, timeout):
    t0 = time.time()
    try:
        # own process group so a timeout can kill cursor-agent AND its worker-server children (no orphans)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    except FileNotFoundError:
        return {"result": "", "error": f"{CURSOR_BIN} not found (is the Cursor CLI installed?)",
                "model": m, "duration_s": round(time.time() - t0, 1)}
    try:
        stdout, stderr = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)    # kill the whole group, not just the parent
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            p.communicate(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        return {"result": "", "error": "timeout", "model": m, "duration_s": round(time.time() - t0, 1)}
    dur = round(time.time() - t0, 1)
    data = _parse_result_json(stdout)
    if not data:
        tail = (stdout or stderr or "")[-300:]
        return {"result": tail, "error": "parse:no-json", "model": m, "duration_s": dur}
    res = data.get("result") or data.get("text") or ""
    low = res.lower()
    if data.get("is_error") or data.get("subtype") == "error":
        rl = any(k in low for k in ("rate limit", "usage limit", "quota", "too many requests"))
        return {"result": res, "error": "rate-limited" if rl else "agent-error", "model": m, "duration_s": dur}
    if any(k in low for k in ("usage limit", "rate limit", "quota exceeded")):
        return {"result": res, "error": "rate-limited", "model": m, "duration_s": dur}
    return {"result": res, "error": None, "model": m, "session_id": data.get("session_id"),
            "usage": data.get("usage"), "duration_s": dur}


# --- session pool (minimise chat sessions) -----------------------------------------------------------
# A small, PROCESS-LEVEL pool of cursor-agent sessions per context, RESUMED across steps, phases AND
# rounds — so a target that hunts forever keeps ~HUNT_SESSION_POOL sessions total instead of opening a
# new chat every step/round (which ballooned to hundreds and tripped rate-limits). A slot opens a fresh
# session only when: it has never run, it errored/hit a limit, or it passed HUNT_SESSION_MAX_USES turns
# (to avoid context-window bloat). Slots are leased with a lock so parallel workers never share one.
_POOL_LOCK = threading.Lock()
_POOL = {}                                  # context -> [ {id, model, uses, inuse}, ... ]
POOL_SIZE = int(os.environ.get("HUNT_SESSION_POOL", "3"))          # concurrent sessions per context
MAX_SESSION_USES = int(os.environ.get("HUNT_SESSION_MAX_USES", "25"))


def _enforce_pool(m):
    pool = [x.strip() for x in os.environ.get("CURSOR_HUNT_MODELS", "").split(",") if x.strip()]
    if pool and m and m not in pool:        # never use an off-pool model (e.g. a stale default)
        return _pick_model()
    return m


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


def _sess_dir(context):
    """Per-target session directory: <base>/_sessions/<slug>/ — isolated last-state for each target."""
    d = os.path.join(os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")),
                     "_sessions", _slug(context))
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _pool_file(context):
    return os.path.join(_sess_dir(context), "state.json")


def _load_pool_ids(context):
    try:
        return json.load(open(_pool_file(context))).get("ids", [])
    except Exception:  # noqa: BLE001
        return []


def _persist_pool(context):
    """Save THIS target's live session ids (per-target file) so stop+rerun RESUMES them, no new sessions.
    Snapshot under the lock (no mid-iteration mutation) + atomic write (no torn file under concurrency)."""
    try:
        with _POOL_LOCK:
            slots = list(_POOL.get(context, []))
            ids = [s["id"] for s in slots if s.get("id")]
            model = slots[0].get("model") if slots else None
        path = _pool_file(context)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"context": context, "ids": ids, "ts": time.time(), "model": model}, fh)
        os.replace(tmp, path)                   # atomic: readers never see a half-written file
    except Exception:  # noqa: BLE001
        pass


def _session_alive(sid):
    """True iff the session id exists on disk in any cursor store. cursor-agent --resume on a DEAD id
    does NOT error — it silently starts a zero-context session under the same id (the 'lost connection'
    symptom), so existence-on-disk is the only reliable liveness check before resuming."""
    if not sid:
        return False
    try:
        import sessions as SESS
        return SESS.is_alive(sid)
    except Exception:  # noqa: BLE001
        return True                     # if we can't check, don't break the happy path


def _acquire(context):
    with _POOL_LOCK:
        slots = _POOL.setdefault(context, [])
        if not slots:                       # first use in this process: seed from the persisted pool
            for sid in _load_pool_ids(context)[:POOL_SIZE]:
                if _session_alive(sid):     # skip dead persisted ids — resuming one loses all context
                    slots.append({"id": sid, "model": None, "uses": 0, "inuse": False})
        for sl in slots:
            if not sl["inuse"]:
                sl["inuse"] = True
                return sl
        if len(slots) < POOL_SIZE:
            sl = {"id": None, "model": None, "uses": 0, "inuse": True}
            slots.append(sl)
            return sl
    return {"id": None, "model": None, "uses": 0, "inuse": True, "transient": True}   # burst overflow


def _release(sl):
    with _POOL_LOCK:
        sl["inuse"] = False


def session_stats():
    """How many sessions the pool is holding (for tracking)."""
    with _POOL_LOCK:
        return {ctx: len(slots) for ctx, slots in _POOL.items()}


def _cmd(task, model, resume_id=None):
    if resume_id:
        return [CURSOR_BIN, "--resume", resume_id, "-p", task, "--output-format", "json", "-f"]
    return [CURSOR_BIN, "-p", task, "--output-format", "json", "-f"] + (["--model", model] if model else [])


def run_agent(task, context=None, skills_on=False, model=None, max_turns=40, timeout=600, attempts=2,
              resume_id=None):
    """Run a headless Cursor agent, REUSING a pooled session for `context` (far fewer chat sessions, far
    less rate-limiting). A fresh session opens only on first use, error/limit, or after
    HUNT_SESSION_MAX_USES turns. context=None => a one-shot ephemeral session (e.g. provisioning).
    resume_id => one-shot run resuming THAT session (used by the verify fix-chat; no pool involved).
    Returns {result, error, model, session_id, reused, ...}."""
    if os.environ.get("HUNT_MOCK_AGENT") == "1":
        m = _enforce_pool(model or _pick_model())
        return {"result": os.environ.get("HUNT_MOCK_RESULT", "```json\n[]\n```"),
                "error": None, "model": m or "mock", "duration_s": 0.0, "reused": False,
                "session_id": resume_id}

    if resume_id:                           # explicit resume (fix-chat): bypass the pool entirely
        m = _enforce_pool(model or _pick_model())
        r = _run_once(_cmd(task, m, resume_id=resume_id), m, timeout)
        r.setdefault("model", m)
        r["reused"] = True
        return r

    sl = _acquire(context) if context is not None else {"id": None, "model": None, "uses": 0}
    try:
        reuse = bool(sl["id"] and sl["uses"] < MAX_SESSION_USES and not model)
        if reuse and not _session_alive(sl["id"]):
            # dead pooled session (its on-disk dir is gone) — resuming it would silently restart with
            # zero context; drop it so a fresh session is opened and its NEW id persisted instead.
            sl.update(id=None, model=None, uses=0)
            reuse = False
        if reuse:
            m, cmd = sl["model"], _cmd(task, sl["model"], resume_id=sl["id"])
        else:                               # fresh session (rotate to next approved-pool model)
            m = _enforce_pool(model or _pick_model())
            sl.update(id=None, model=m, uses=0)
            cmd = _cmd(task, m)
        r = {}
        for attempt in range(1, max(1, attempts) + 1):
            r = _run_once(cmd, m, timeout)
            if r.get("session_id"):
                sl["id"] = r["session_id"]  # remember so the next call --resume's it (across rounds too)
            if r.get("error") not in _RETRYABLE or attempt >= attempts:
                break
            time.sleep(2 * attempt)
            r["retried"] = attempt
            sl["id"] = None
            cmd = _cmd(task, m)             # retry on a fresh session
        if r.get("error"):                  # drop the session on error/limit; next call opens a fresh one
            sl.update(id=None, model=None, uses=0)
        else:
            sl["uses"] += 1
        if context is not None:
            _persist_pool(context)          # keep this target's state current so stop+rerun resumes it
        r.setdefault("model", m)
        r["reused"] = reuse
        return r
    finally:
        if context is not None:
            _release(sl)


def extract_json(text):
    """Pull the last valid JSON array/object out of an agent reply."""
    if not text:
        return None
    blocks = re.findall(r"```json\s*(.*?)```", text, re.S)
    blocks += re.findall(r"```\s*(\[.*?\]|\{.*?\})\s*```", text, re.S)
    for b in reversed(blocks):
        try:
            return json.loads(b.strip())
        except Exception:
            pass
    for b in reversed(re.findall(r"(\[.*\]|\{.*\})", text, re.S)):
        try:
            return json.loads(b)
        except Exception:
            pass
    return None


if __name__ == "__main__":
    # offline self-test of the JSON extractor + result parser (no agent call)
    assert extract_json('blah ```json\n[{"a":1}]\n``` end') == [{"a": 1}]
    assert extract_json('text {"x": "y"} more') == {"x": "y"}
    assert extract_json("no json here") is None
    assert extract_json('first {"a":1} then ```json\n{"b":2}\n```') == {"b": 2}
    assert _parse_result_json('{"type":"result","is_error":false,"result":"PONG"}')["result"] == "PONG"
    assert _parse_result_json('warning line\n{"is_error":false,"result":"ok"}')["result"] == "ok"
    assert _parse_result_json("") is None
    print("agent.py (cursor) self-test: PASS")
