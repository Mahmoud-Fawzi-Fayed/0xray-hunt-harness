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
    """cursor-agent --output-format json prints one result object, or (on a long tool-using run) a
    stream of JSON events with the result last. A single json.loads of the whole buffer fails on
    that stream, and a greedy `{.*}` span joins the events into invalid JSON — that was the
    reviewer's `parse:no-json`."""
    stdout = (stdout or "").strip().lstrip("\ufeff")
    if not stdout:
        return None
    try:
        obj = json.loads(stdout)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    dec = json.JSONDecoder()
    objs, i, n = [], 0, len(stdout)
    while i < n:
        while i < n and stdout[i] not in "{[":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(stdout, i)
        except json.JSONDecodeError:
            i += 1
            continue
        if isinstance(obj, dict):
            objs.append(obj)
        i = max(end, i + 1)
    if not objs:
        return None
    for obj in reversed(objs):
        if obj.get("type") == "result" or "result" in obj or "text" in obj:
            return obj
    return objs[-1]


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
        # SIGTERM first so cursor-agent can flush a result / session_id; SIGKILL only if it won't die.
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        stdout, stderr = "", ""
        try:
            stdout, stderr = p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                stdout, stderr = p.communicate(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        data = _parse_result_json(stdout)
        if data and not data.get("is_error") and (data.get("result") or data.get("text")):
            return {"result": data.get("result") or data.get("text") or "", "error": None,
                    "model": data.get("model") or m, "session_id": data.get("session_id"),
                    "usage": data.get("usage"), "duration_s": round(time.time() - t0, 1)}
        sid = data.get("session_id") if isinstance(data, dict) else None
        return {"result": "", "error": "timeout", "model": m, "session_id": sid,
                "duration_s": round(time.time() - t0, 1)}
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
    return {"result": res, "error": None, "model": data.get("model") or m,
            "session_id": data.get("session_id"), "usage": data.get("usage"), "duration_s": dur}


# --- session pool (minimise chat sessions) -----------------------------------------------------------
# A small, PROCESS-LEVEL pool of cursor-agent sessions per context, RESUMED across steps, phases AND
# rounds — so a target that hunts forever keeps ~HUNT_SESSION_POOL sessions total instead of opening a
# new chat every step/round (which ballooned to hundreds and tripped rate-limits). A slot opens a fresh
# session only when: it has never run, it errored/hit a limit, or it passed HUNT_SESSION_MAX_USES turns
# (to avoid context-window bloat). Slots are leased with a lock so parallel workers never share one.
_POOL_LOCK = threading.Lock()
_POOL = {}                                  # context -> [ {id, model, uses, inuse}, ... ]
POOL_SIZE = int(os.environ.get("HUNT_SESSION_POOL", "3"))          # reused sessions kept per target
MAX_SESSION_USES = int(os.environ.get("HUNT_SESSION_MAX_USES", "25"))
# A resumed chat older than this is retired instead of reused. Uses reset on process restart, so
# without an age cap one slot keeps an 18-hour transcript forever and it looks like a live hunt.
MAX_SESSION_AGE_MIN = int(os.environ.get("HUNT_SESSION_MAX_AGE_MIN", "360"))


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


def _created_file():
    """Registry of session ids the HARNESS itself created. Cleanup (watchdog) consults this so it can
    remove ONLY harness sessions and never the operator's interactive/IDE sessions (which never land
    here). Lives next to the pools: <base>/_sessions/_created.json."""
    return os.path.join(
        os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")),
        "_sessions", "_created.json")


def _register_created(sid):
    """Best-effort, idempotent, atomic record of a harness-created session id. Never raises into the
    hunt loop — a failure here only means a session leaks (safe), never that one is wrongly deleted."""
    if not sid:
        return
    try:
        p = _created_file()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with _POOL_LOCK:
            try:
                reg = json.load(open(p))
                if not isinstance(reg, dict):
                    reg = {}
            except Exception:  # noqa: BLE001
                reg = {}
            if str(sid) in reg:
                return
            reg[str(sid)] = time.time()
            tmp = p + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(reg, fh)
            os.replace(tmp, p)              # atomic: a concurrent reader never sees a torn file
    except Exception:  # noqa: BLE001
        pass


def _load_pool_ids(context):
    try:
        return json.load(open(_pool_file(context))).get("ids", [])
    except Exception:  # noqa: BLE001
        return []


def _load_pool_models(context):
    """{id: model} for persisted pool sessions, so a RESUMED session keeps its model LABEL across
    restarts. Without this, every resumed session logs model=None in the activity panel even though
    cursor-agent is still running it on its original approved-pool model."""
    try:
        m = json.load(open(_pool_file(context))).get("models", {})
        return m if isinstance(m, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _load_pool_uses(context):
    """{id: use count} so HUNT_SESSION_MAX_USES survives a process restart. Without this, every
    restart resets the counter to 0 and a slot resumes the same chat forever."""
    try:
        m = json.load(open(_pool_file(context))).get("uses", {})
        return m if isinstance(m, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _persist_pool(context):
    """Save THIS target's live session ids (per-target file) so stop+rerun RESUMES them, no new sessions.
    Snapshot under the lock (no mid-iteration mutation) + atomic write (no torn file under concurrency)."""
    try:
        with _POOL_LOCK:
            slots = list(_POOL.get(context, []))
            ids = [s["id"] for s in slots if s.get("id")]
            model = slots[0].get("model") if slots else None
            models = {s["id"]: s["model"] for s in slots if s.get("id") and s.get("model")}
            uses = {s["id"]: int(s.get("uses") or 0) for s in slots if s.get("id")}
        path = _pool_file(context)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"context": context, "ids": ids, "models": models, "uses": uses,
                       "ts": time.time(), "model": model}, fh)
        os.replace(tmp, path)                   # atomic: readers never see a half-written file
    except Exception:  # noqa: BLE001
        pass


def _ids_to_retire(orphans, kept):
    """Session ids a finished step abandoned. The id the slot is keeping is never retired."""
    out = []
    for sid in orphans:
        if sid and sid != kept and sid not in out:
            out.append(sid)
    return out


def _session_ancient(sid):
    """True when the conversation itself has not moved in MAX_SESSION_AGE_MIN. Directory mtime is
    not used — opening the store rewrites it."""
    if not sid or MAX_SESSION_AGE_MIN <= 0:
        return False
    try:
        import sessions as SESS
        ts = SESS._conversation_ts(sid)
    except Exception:  # noqa: BLE001
        return False
    if not ts:
        return False
    return (time.time() - ts) > MAX_SESSION_AGE_MIN * 60


def _retire(sid):
    """Delete a harness chat this process is done with. Never raises. An id another slot still
    holds is left alone; sessions.drop_ids also refuses anything still listed in a pool file, so
    the caller must persist the pool BEFORE retiring a replaced id."""
    if not sid:
        return
    try:
        with _POOL_LOCK:
            for slots in _POOL.values():
                for s in slots:
                    if s.get("id") == sid:
                        return
        import sessions as SESS
        SESS.drop_ids([sid])
    except Exception:  # noqa: BLE001
        pass


def _retire_all(ids):
    for sid in ids:
        _retire(sid)


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
    """Lease one pooled slot. A persisted id that is dead, exhausted, or older than the age cap is
    not resumed — it is retired after the pool file is rewritten, so it cannot sit on disk forever.
    When every slot is busy, the extra call is transient: its chat is deleted when that call ends
    (see run_agent) instead of becoming a permanent extra session."""
    retire = []
    chosen = None
    with _POOL_LOCK:
        slots = _POOL.setdefault(context, [])
        if not slots:                       # first use in this process: seed from the persisted pool
            models = _load_pool_models(context)
            uses = _load_pool_uses(context)
            for sid in _load_pool_ids(context)[:POOL_SIZE]:
                used = int(uses.get(sid) or 0)
                if (not _session_alive(sid) or used >= MAX_SESSION_USES or _session_ancient(sid)):
                    retire.append(sid)      # do not resume a dead, exhausted, or stale chat
                    continue
                slots.append({"id": sid, "model": models.get(sid), "uses": used, "inuse": False})
        for sl in slots:
            if not sl["inuse"]:
                sl["inuse"] = True
                chosen = sl
                break
        if chosen is None and len(slots) < POOL_SIZE:
            chosen = {"id": None, "model": None, "uses": 0, "inuse": True}
            slots.append(chosen)
        elif chosen is None:
            chosen = {"id": None, "model": None, "uses": 0, "inuse": True, "transient": True}
    if retire:
        _persist_pool(context)              # drop retired ids from the file before unlinking them
        _retire_all(retire)
    return chosen


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
        err = (os.environ.get("HUNT_MOCK_ERROR") or "").strip() or None
        return {"result": os.environ.get("HUNT_MOCK_RESULT", "```json\n[]\n```"),
                "error": err, "model": m or "mock", "duration_s": 0.0, "reused": bool(resume_id),
                "session_id": resume_id or "mock-session"}

    if resume_id:                           # explicit resume (fix-chat): bypass the pool entirely
        m = _enforce_pool(model or _pick_model())
        r = _run_once(_cmd(task, m, resume_id=resume_id), m, timeout)
        r.setdefault("model", m)
        r["reused"] = True
        _register_created(r.get("session_id") or resume_id)   # harness-owned: safe to auto-prune later
        return r

    # context=None is a one-shot (review, verify, provisioning). It must not stay on disk.
    ephemeral = context is None
    sl = _acquire(context) if not ephemeral else {"id": None, "model": None, "uses": 0, "ephemeral": True}
    orphans = []
    try:
        reuse = bool(sl.get("id") and sl["uses"] < MAX_SESSION_USES and not model
                     and not sl.get("transient") and not ephemeral)
        if reuse and not _session_alive(sl["id"]):
            # dead pooled session — resuming it silently starts an empty chat under the same id
            orphans.append(sl["id"])
            sl.update(id=None, model=None, uses=0)
            reuse = False
        if reuse:
            m, cmd = sl["model"], _cmd(task, sl["model"], resume_id=sl["id"])
        else:                               # fresh session (first use, failover, exhausted, or one-shot)
            if sl.get("id"):
                orphans.append(sl["id"])    # the chat being replaced is finished — close it
            m = _enforce_pool(model or _pick_model())
            sl.update(id=None, model=m, uses=0)
            cmd = _cmd(task, m)
        r = {}
        for attempt in range(1, max(1, attempts) + 1):
            r = _run_once(cmd, m, timeout)
            if r.get("session_id"):
                if sl.get("id") and sl["id"] != r["session_id"]:
                    orphans.append(sl["id"])
                sl["id"] = r["session_id"]  # remember so the next call --resume's it (across rounds too)
                _register_created(r["session_id"])   # harness-owned id -> eligible for safe auto-prune
            if r.get("model") and not sl.get("model"):
                sl["model"] = r["model"]    # learn a resumed session's model -> labeled in activity + persisted
            if r.get("error") not in _RETRYABLE or attempt >= attempts:
                break
            time.sleep(2 * attempt)
            r["retried"] = attempt
            if sl.get("id"):
                orphans.append(sl["id"])    # failed attempt is not reused
            sl["id"] = None
            cmd = _cmd(task, m)             # retry on a fresh session
        if r.get("error"):                  # drop the session on error/limit; next call opens a fresh one
            if sl.get("id"):
                orphans.append(sl["id"])
            sl.update(id=None, model=None, uses=0)
        else:
            sl["uses"] = int(sl.get("uses") or 0) + 1
        # One-shots and burst overflow are outside the per-target cap. Close them when the call ends.
        if ephemeral or sl.get("transient"):
            if sl.get("id"):
                orphans.append(sl["id"])
            sl["id"] = None
        if context is not None and not sl.get("transient"):
            _persist_pool(context)          # pool file first, so the replaced id is no longer protected
        _retire_all(_ids_to_retire(orphans, sl.get("id")))
        r.setdefault("model", m)
        r["reused"] = reuse
        return r
    finally:
        if context is not None and not sl.get("transient"):
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
    stream = ('{"type":"system","subtype":"init"}\n'
              '{"type":"assistant","message":{"content":"looking"}}\n'
              '{"type":"result","is_error":false,"result":"```json\\n{\\"score_0_10\\": 4}\\n```"}')
    got = _parse_result_json(stream)
    assert got and got.get("type") == "result" and "score_0_10" in got["result"], got
    assert _ids_to_retire(["old", "old", None, "kept"], "kept") == ["old"]
    assert _ids_to_retire(["only"], None) == ["only"]
    print("agent.py (cursor) self-test: PASS")
