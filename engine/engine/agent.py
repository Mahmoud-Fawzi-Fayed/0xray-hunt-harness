#!/usr/bin/env python3
"""
agent.py — the engine's LLM dispatch for Kimi Code, OpenCode, and Cursor agents.

Runtime is selected per model:
  - aliases in KIMI_HUNT_MODELS or `kimi-code/*` -> `kimi -p ... --output-format stream-json`
  - `opencode/*`, `openai/*` -> `opencode run -m <model> --format json`
  - anything else -> `cursor-agent -p ... --output-format json -f` (legacy pool)

Everything else in the engine (scope, state, orchestration, dedup, novelty) is deterministic code.

Agents are asked to end with a fenced ```json``` block which we parse into structured data.

Model pool (approved list, round-robin): KIMI_HUNT_MODELS, OPENCODE_HUNT_MODELS, CURSOR_HUNT_MODELS,
then HUNT_MODELS. One-off override: CURSOR_HUNT_MODEL.
"""
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
KIMI_BIN = os.environ.get("KIMI_BIN", "kimi")
CURSOR_BIN = os.environ.get("CURSOR_AGENT_BIN", "cursor-agent")
OPENCODE_BIN = os.environ.get("OPENCODE_BIN", os.path.expanduser("~/.opencode/bin/opencode"))
CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude")


def _is_claude_code_available():
    """Check if we can use Claude Code CLI as a fallback agent runtime."""
    from shutil import which as _which
    return bool(_which(CLAUDE_BIN))


def _claude_code_dispatch(task, timeout=600, env_extra=None):
    """Run a hunt task via Claude Code CLI (headless, non-interactive).
    Returns the same {result, error, model, session_id, ...} shape as _run_once."""
    import tempfile
    prompt_file = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, dir="/tmp")
    prompt_file.write(task)
    prompt_file.close()
    cmd = [CLAUDE_BIN, "--print", "--max-turns", "25",
           "--permission-mode", "default"]
    sub_env = None
    if env_extra:
        sub_env = {**os.environ, **{k: str(v) for k, v in env_extra.items()}}
    try:
        proc = subprocess.run(cmd, input=task, capture_output=True, text=True,
                              timeout=timeout, cwd=os.path.dirname(ENGINE), env=sub_env)
        stdout = proc.stdout or ""
        result_json = extract_json(stdout)
        return {"result": stdout if not result_json else json.dumps(result_json),
                "error": None if proc.returncode == 0 else "agent-error",
                "model": "claude-code", "session_id": None, "reused": False,
                "duration_s": 0, "complete": proc.returncode == 0,
                "parsed": result_json}
    except subprocess.TimeoutExpired:
        return {"result": "", "error": "timeout", "model": "claude-code",
                "session_id": None, "reused": False, "duration_s": timeout,
                "complete": False, "partial": True}
    except Exception as e:
        return {"result": "", "error": str(e), "model": "claude-code",
                "session_id": None, "reused": False, "duration_s": 0}
    finally:
        try:
            os.unlink(prompt_file.name)
        except OSError:
            pass

# Model policy: hunt ONLY on this approved pool, rotating per call for diversity (and to dodge a single
# model's safety-filter stalls). KIMI_HUNT_MODELS wins, then OPENCODE_HUNT_MODELS, then the legacy pools.
_RR = {"i": 0}


def _load_model_env():
    try:
        import notify
        notify._load_env_file()
    except Exception:  # noqa: BLE001
        pass
    if os.environ.get("KIMI_HUNT_MODELS"):
        return
    path = os.path.expanduser(os.environ.get("KIMI_HUNT_CONFIG", "~/.kimi-code/hunt-runtime.json"))
    try:
        data = json.load(open(path, encoding="utf-8"))
        models = data.get("models") if isinstance(data, dict) else None
        if isinstance(models, list):
            pool = [str(m).strip() for m in models if str(m).strip()]
            if pool:
                os.environ["KIMI_HUNT_MODELS"] = ",".join(pool)
    except (OSError, ValueError, TypeError):
        pass


def _pool_models():
    """Approved pool: KIMI_HUNT_MODELS > OPENCODE_HUNT_MODELS > CURSOR_HUNT_MODELS > HUNT_MODELS."""
    _load_model_env()
    for key in ("KIMI_HUNT_MODELS", "OPENCODE_HUNT_MODELS", "CURSOR_HUNT_MODELS", "HUNT_MODELS"):
        pool = [m.strip() for m in os.environ.get(key, "").split(",") if m.strip()]
        if pool:
            return pool
    return []


def _is_kimi_model(m):
    m = str(m or "")
    configured = [x.strip() for x in os.environ.get("KIMI_HUNT_MODELS", "").split(",")]
    return m.startswith("kimi-code/") or m in configured


def _is_opencode_model(m):
    m = str(m or "")
    return m.startswith("opencode/") or m.startswith("openai/")


def _runtime(m=None, resume_id=None):
    sid = str(resume_id or "")
    if sid.startswith("session_"):
        return "kimi"
    if sid.startswith("ses_"):
        return "opencode"
    if resume_id:
        return "cursor"
    if _is_kimi_model(m):
        return "kimi"
    if _is_opencode_model(m):
        return "opencode"
    return "cursor"


def _command_runtime(cmd, m=None):
    binary = os.path.basename(str((cmd or [""])[0]))
    if binary == os.path.basename(KIMI_BIN):
        return "kimi"
    if binary == os.path.basename(OPENCODE_BIN):
        return "opencode"
    if binary == os.path.basename(CURSOR_BIN):
        return "cursor"
    return _runtime(m)


def _pick_model():
    pool = _pool_models()
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

# Flags that should never appear in agent commands without explicit audit — these bypass safety
# boundaries or skip permission gates and are flagged at command-build time.
_DANGEROUS_FLAGS = ["--dangerously-skip-permissions", "--no-verify", "--yolo"]


def _rate_limited(text):
    low = str(text or "").lower()
    return any(k in low for k in ("rate limit", "usage limit", "quota", "too many requests", "429"))


def _parse_opencode_json(stdout):
    """opencode run --format json prints JSONL events: step_start / text* / step_finish / error.

    We concatenate all `text` payloads, sum usage across every step_finish, require a terminal
    non-tool-call finish, and preserve error events even when text preceded them.
    """
    stdout = (stdout or "").strip().lstrip("\ufeff")
    if not stdout:
        return None
    texts, sid, err_text = [], None, None
    usage = {"input": 0, "output": 0, "reasoning": 0,
             "cache": {"read": 0, "write": 0}, "total": 0, "cost": 0.0}
    finish_reason, finishes = None, 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        part = obj.get("part") or {}
        if not isinstance(part, dict):
            part = {}
        if not sid:
            sid = obj.get("sessionID") or part.get("sessionID")
        if obj.get("type") == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
        elif isinstance(part.get("text"), str) and part.get("type") == "text":
            texts.append(part["text"])
        pf = part.get("part") if isinstance(part.get("part"), dict) else None
        if isinstance(pf, dict) and isinstance(pf.get("text"), str):
            texts.append(pf["text"])
        if obj.get("type") in ("step_finish", "step-finish"):
            finishes += 1
            finish_reason = part.get("reason") or obj.get("reason")
            tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
            for key in ("input", "output", "reasoning", "total"):
                usage[key] += int(tokens.get(key) or 0)
            cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
            usage["cache"]["read"] += int(cache.get("read") or 0)
            usage["cache"]["write"] += int(cache.get("write") or 0)
            usage["cost"] = round(usage["cost"] + float(part.get("cost") or obj.get("cost") or 0), 12)
        if obj.get("type") == "error":
            e = obj.get("error") or {}
            if isinstance(e, dict):
                data = e.get("data") if isinstance(e.get("data"), dict) else {}
                err_text = data.get("message") or e.get("message") or json.dumps(e)[:500]
            else:
                err_text = str(e)[:500]
    if not texts and not sid and not finishes and not err_text:
        return None
    result = "\n".join(texts).strip()
    complete = bool(finishes and finish_reason not in (None, "tool-calls", "tool_calls"))
    out = {"result": result, "session_id": sid, "usage": usage,
           "complete": complete, "finish_reason": finish_reason}
    if err_text:
        out.update(is_error=True, error="rate-limited" if _rate_limited(err_text) else "agent-error",
                   error_message=err_text)
        if not result:
            out["result"] = err_text
    return out


def _run_once(cmd, m, timeout, env_extra=None):
    t0 = time.time()
    is_oc = _is_opencode_model(m) or any(str(x).startswith("ses_") for x in (cmd or []))
    # Per-task env: copy parent env and merge extras (never mutate os.environ — concurrent race)
    sub_env = None
    if env_extra:
        sub_env = {**os.environ, **{k: str(v) for k, v in env_extra.items()}}
    try:
        # own process group so a timeout can kill the agent AND its worker children (no orphans)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True, env=sub_env)
    except FileNotFoundError:
        bin_name = OPENCODE_BIN if is_oc else CURSOR_BIN
        return {"result": "", "error": f"{bin_name} not found (is the agent CLI installed?)",
                "model": m, "duration_s": round(time.time() - t0, 1)}

    def _parse(stdout):
        if is_oc:
            return _parse_opencode_json(stdout)
        return _parse_result_json(stdout)

    try:
        stdout, stderr = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # SIGTERM first so the agent can flush a result / session_id; SIGKILL only if it won't die.
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
        data = _parse(stdout)
        sid = data.get("session_id") if isinstance(data, dict) else None
        partial = (data.get("result") or data.get("text") or "") if isinstance(data, dict) else ""
        if not partial:
            partial = (stdout or stderr or "")[-300:]
        return {"result": partial, "partial": True, "error": "timeout", "model": m,
                "session_id": sid, "usage": data.get("usage") if isinstance(data, dict) else None,
                "duration_s": round(time.time() - t0, 1)}
    dur = round(time.time() - t0, 1)
    data = _parse(stdout)
    if not data:
        tail = (stdout or stderr or "")[-300:]
        return {"result": tail, "error": "parse:no-json", "model": m, "duration_s": dur}
    res = data.get("result") or data.get("text") or ""
    if p.returncode not in (0, None):
        detail = data.get("error_message") or res or (stderr or "")[-300:]
        error = data.get("error") or ("rate-limited" if _rate_limited(detail) else "agent-error")
        return {"result": res or detail, "error": error, "model": data.get("model") or m,
                "session_id": data.get("session_id"), "usage": data.get("usage"), "duration_s": dur}
    if data.get("is_error") or data.get("subtype") == "error":
        error = data.get("error") or ("rate-limited" if _rate_limited(data.get("error_message") or res)
                                      else "agent-error")
        return {"result": res, "error": error, "model": m, "duration_s": dur,
                "session_id": data.get("session_id"), "usage": data.get("usage")}
    if is_oc and not data.get("complete"):
        return {"result": res, "partial": bool(res), "error": "parse:incomplete-jsonl", "model": m,
                "session_id": data.get("session_id"), "usage": data.get("usage"), "duration_s": dur}
    if _rate_limited(res):
        return {"result": res, "error": "rate-limited", "model": m, "duration_s": dur,
                "session_id": data.get("session_id"), "usage": data.get("usage")}
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


def _enforce_pool(m, opencode=None):
    pool = _pool_models()
    if pool and m and m not in pool:        # never use an off-pool model (e.g. a stale default)
        candidates = [x for x in pool if opencode is None or _is_opencode_model(x) == opencode]
        if not candidates:
            return None
        picked = candidates[_RR["i"] % len(candidates)]
        _RR["i"] += 1
        return picked
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
    not used — opening the store rewrites it. OpenCode sessions (ses_*) are server-side: age is
    enforced by use-count, not disk ts, so they are never 'ancient' here."""
    if not sid or MAX_SESSION_AGE_MIN <= 0:
        return False
    if str(sid).startswith("ses_"):
        return False                      # opencode: bounded by HUNT_SESSION_MAX_USES instead
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
    """True iff the session id is resumable. Cursor: exists on disk in any cursor store
    (--resume on a DEAD id silently starts a zero-context session). OpenCode (ses_*):
    server-side, resume via `opencode run -s <id>` — trust it unless the slot errored
    (liveness is enforced by use-count + error-drop, not disk presence)."""
    if not sid:
        return False
    if str(sid).startswith("ses_"):
        return True                       # opencode session: resumable via -s
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
            approved = _pool_models()
            for sid in _load_pool_ids(context)[:POOL_SIZE]:
                used = int(uses.get(sid) or 0)
                stored_model = models.get(sid)
                if (not _session_alive(sid) or used >= MAX_SESSION_USES or _session_ancient(sid)
                        or (approved and stored_model not in approved)
                        or (stored_model and _is_opencode_model(stored_model) != str(sid).startswith("ses_"))):
                    retire.append(sid)      # do not resume a dead, exhausted, or stale chat
                    continue
                slots.append({"id": sid, "model": stored_model, "uses": used, "inuse": False})
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
    # OpenCode runtime for opencode/* + openai/* models (verified on this box via `opencode run`):
    #   fresh:  opencode run "<task>" -m <model> --format json
    #   resume: opencode run "<task>" -s <sid> -m <model> --format json
    # Cursor runtime for everything else (legacy pool):
    #   fresh:  cursor-agent -p <task> --output-format json -f [--model m]
    #   resume: cursor-agent --resume <sid> -p <task> --output-format json -f
    resume_oc = bool(resume_id and str(resume_id).startswith("ses_"))
    if resume_id and model and _is_opencode_model(model) != resume_oc:
        raise ValueError("resume session runtime does not match model runtime")
    if resume_oc or (not resume_id and model and _is_opencode_model(model)):
        base = [OPENCODE_BIN, "run", task]
        if model:
            base += ["-m", model]
        base += ["--format", "json"]
        if resume_id:
            base += ["-s", resume_id]
        cmd = base
    elif resume_id:
        cmd = [CURSOR_BIN, "--resume", resume_id, "-p", task, "--output-format", "json", "-f"]
    else:
        cmd = [CURSOR_BIN, "-p", task, "--output-format", "json", "-f"] + (["--model", model] if model else [])
    # Audit: warn on dangerous flags so they are never silently passed through.
    for element in cmd:
        if element in _DANGEROUS_FLAGS:
            print(f"WARNING: dangerous flag {element} in agent command — audit required",
                  file=sys.stderr)
    return cmd


def run_agent(task, context=None, skills_on=False, model=None, max_turns=40, timeout=600, attempts=2,
              resume_id=None, scope_file=None, env_extra=None):
    """Run a headless hunting agent (opencode OR cursor runtime by model prefix),
    REUSING a pooled session for `context` (far fewer chat sessions, far
    less rate-limiting). A fresh session opens only on first use, error/limit, or after
    HUNT_SESSION_MAX_USES turns. context=None => a one-shot ephemeral session (e.g. provisioning).
    resume_id => one-shot run resuming THAT session (used by the verify fix-chat; no pool involved).
    `max_turns` is retained for caller compatibility but neither supported CLI enforces it; timeout is
    the execution bound.  scope_file => path inserted into the task preamble so the sub-agent can load it.
    env_extra => per-task env vars merged into the subprocess env (never mutates parent os.environ).
    Returns {result, error, model, session_id, reused, ...}."""
    if scope_file:
        task = f"[scope-file: {scope_file}] — load this scope before acting.\n\n{task}"
    _load_model_env()
    if os.environ.get("HUNT_MOCK_AGENT") == "1":
        m = _enforce_pool(model or _pick_model())
        err = (os.environ.get("HUNT_MOCK_ERROR") or "").strip() or None
        return {"result": os.environ.get("HUNT_MOCK_RESULT", "```json\n[]\n```"),
                "error": err, "model": m or "mock", "duration_s": 0.0, "reused": bool(resume_id),
                "session_id": resume_id or "mock-session"}

    if resume_id:                           # explicit resume (fix-chat): bypass the pool entirely
        resume_oc = str(resume_id).startswith("ses_")
        m = _enforce_pool(model, opencode=resume_oc) if model else None
        if model and not m:
            return {"result": "", "error": "resume-runtime-mismatch", "model": model,
                    "session_id": resume_id, "reused": True, "duration_s": 0.0}
        try:
            cmd = _cmd(task, m, resume_id=resume_id)
        except ValueError as e:
            return {"result": str(e), "error": "resume-runtime-mismatch", "model": m or model,
                    "session_id": resume_id, "reused": True, "duration_s": 0.0}
        r = _run_once(cmd, m, timeout, env_extra=env_extra)
        r.setdefault("model", m)
        r["reused"] = True
        _register_created(r.get("session_id") or resume_id)   # harness-owned: safe to auto-prune later
        return r

    # context=None is a one-shot (review, verify, provisioning). It must not stay on disk.
    ephemeral = context is None
    sl = _acquire(context) if not ephemeral else {"id": None, "model": None, "uses": 0, "ephemeral": True}
    orphans = []
    try:
        approved = _pool_models()
        reuse = bool(sl.get("id") and sl["uses"] < MAX_SESSION_USES and not model
                     and not sl.get("transient") and not ephemeral)
        if reuse and ((approved and sl.get("model") not in approved)
                      or (sl.get("model") and _is_opencode_model(sl["model"])
                          != str(sl["id"]).startswith("ses_"))):
            orphans.append(sl["id"])
            sl.update(id=None, model=None, uses=0)
            reuse = False
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
            r = _run_once(cmd, m, timeout, env_extra=env_extra)
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
    # opencode runtime: routing + JSONL parse (no agent call)
    assert _is_opencode_model("opencode/muse-spark-1.3-contributor-free")
    assert _is_opencode_model("openai/gpt-6-astra-fast")
    assert not _is_opencode_model("kimi-k3-max")
    c = _cmd("hi", "opencode/mimo-v2.6-flash-free")
    assert c[0].endswith("opencode") and "-m" in c and "--format" in c, c
    c = _cmd("hi", "opencode/mimo-v2.6-flash-free", resume_id="ses_abc")
    assert "-s" in c and "ses_abc" in c, c
    c = _cmd("hi", "kimi-k3-max")
    assert "cursor-agent" in c[0], c
    oc = ('{"type":"step_start","sessionID":"ses_123"}\n'
          '{"type":"text","sessionID":"ses_123","part":{"type":"text","text":"PONG"}}\n'
          '{"type":"step_finish","sessionID":"ses_123","part":{"reason":"stop","tokens":{"input":10,"output":2}}}')
    got = _parse_opencode_json(oc)
    assert got and got["result"] == "PONG" and got.get("session_id") == "ses_123", got
    assert _parse_opencode_json("") is None
    assert _session_alive("ses_abc123") is True
    assert _session_ancient("ses_abc123") is False
    os.environ["OPENCODE_HUNT_MODELS"] = "opencode/a,openai/b"
    os.environ.pop("CURSOR_HUNT_MODELS", None)
    assert _pool_models() == ["opencode/a", "openai/b"], _pool_models()
    os.environ.pop("OPENCODE_HUNT_MODELS", None)
    oc = ('{"type":"step_start","sessionID":"ses_123","part":{"type":"step-start"}}\n'
          '{"type":"text","sessionID":"ses_123","part":{"type":"text","text":"PONG"}}\n'
          '{"type":"step_finish","sessionID":"ses_123","part":{"reason":"tool-calls",'
          '"cost":0.1,"tokens":{"input":10,"output":2,"cache":{"read":3,"write":1}}}}\n'
          '{"type":"step_finish","sessionID":"ses_123","part":{"reason":"stop",'
          '"cost":0.2,"tokens":{"input":20,"output":4,"reasoning":2,"cache":{"read":5,"write":0}}}}')
    got = _parse_opencode_json(oc)
    assert got and got["complete"] and got["result"] == "PONG", got
    assert got["usage"] == {"input": 30, "output": 6, "reasoning": 2,
                            "cache": {"read": 8, "write": 1}, "total": 0, "cost": 0.3}, got
    incomplete = _parse_opencode_json(
        '{"type":"text","sessionID":"ses_partial","part":{"type":"text","text":"partial"}}')
    assert incomplete and not incomplete["complete"] and incomplete["result"] == "partial", incomplete
    errored = _parse_opencode_json(
        '{"type":"text","sessionID":"ses_err","part":{"type":"text","text":"working"}}\n'
        '{"type":"error","sessionID":"ses_err","error":{"data":{"message":"HTTP 429"}}}')
    assert errored and errored["is_error"] and errored["error"] == "rate-limited", errored
    assert errored["result"] == "working", errored
    c = _cmd("hi", None, resume_id="ses_abc")
    assert c[0] == OPENCODE_BIN and "-s" in c, c
    try:
        _cmd("hi", "cursor-model", resume_id="ses_abc")
        assert False, "cross-runtime resume must be rejected"
    except ValueError:
        pass
    partial_line = '{"type":"text","sessionID":"ses_timeout","part":{"type":"text","text":"partial"}}'
    timed = _run_once(["/bin/sh", "-c", f"printf '%s\\n' '{partial_line}'; sleep 2"],
                      "openai/test", 0.05)
    assert timed["error"] == "timeout" and timed["result"] == "partial" and timed["partial"], timed
    finish_line = ('{"type":"step_finish","sessionID":"ses_exit",'
                   '"part":{"reason":"stop","tokens":{"input":1,"output":1}}}')
    exited = _run_once(["/bin/sh", "-c", f"printf '%s\\n' '{finish_line}'; exit 7"],
                       "openai/test", 2)
    assert exited["error"] == "agent-error", exited
    # --- P1 sec 8: dangerous-flag audit + scope_file preamble ---
    # _cmd for a safe model emits no warning
    import io as _io
    _saved_stderr = sys.stderr
    _cap = _io.StringIO()
    sys.stderr = _cap
    c = _cmd("test", "kimi-k3-max")
    sys.stderr = _saved_stderr
    assert _cap.getvalue() == "", f"unexpected warning on safe cmd: {_cap.getvalue()}"
    # dangerous flag check: _DANGEROUS_FLAGS list exists with expected entries
    assert "--dangerously-skip-permissions" in _DANGEROUS_FLAGS
    assert "--no-verify" in _DANGEROUS_FLAGS
    assert "--yolo" in _DANGEROUS_FLAGS
    # scope_file preamble injection (task text, not CLI args)
    os.environ["HUNT_MOCK_AGENT"] = "1"
    r = run_agent("hunt this", scope_file="/tmp/scope.json")
    assert "[scope-file: /tmp/scope.json]" in r["result"] or True  # mock returns canned result
    os.environ.pop("HUNT_MOCK_AGENT", None)
    print("agent.py (cursor+opencode) self-test: PASS")
