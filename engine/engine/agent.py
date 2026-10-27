#!/usr/bin/env python3
"""Dispatch hunt tasks to the configured active AI command.

HUNT_AGENT_CMD is an argv template with optional {task}, {model}, and {resume}
placeholders. Without {task}, the prompt is sent on stdin. HUNT_MODELS is an
optional pool of opaque labels. No provider, model, or fallback CLI is inferred.
"""
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
_RR = {"i": 0}
_RETRYABLE = {"parse:no-json", "parse:incomplete-jsonl", "rate-limited", "agent-error"}
_DANGEROUS_FLAGS = ["--dangerously-skip-permissions", "--no-verify", "--yolo"]


def _load_model_env():
    try:
        import notify
        notify._load_env_file()
    except Exception:
        pass


def _template():
    _load_model_env()
    return os.environ.get("HUNT_AGENT_CMD", "").strip()


def _runtime(_model=None, _resume_id=None):
    template = _template()
    return hashlib.sha256(template.encode()).hexdigest()[:16] if template else "unconfigured"


def _command_runtime(_cmd=None, _model=None):
    return _runtime()


def runtime_info():
    template = _template()
    return {"configured": bool(template), "runtime_id": _runtime(),
            "executable": os.path.basename(shlex.split(template)[0]) if template else "",
            "supports_resume": "{resume}" in template,
            "prompt_transport": "argv" if "{task}" in template else "stdin"}


def _pool_models():
    _load_model_env()
    return [m.strip() for m in os.environ.get("HUNT_MODELS", "").split(",") if m.strip()]


def _pick_model():
    pool = _pool_models()
    if not pool:
        return None
    model = pool[_RR["i"] % len(pool)]
    _RR["i"] += 1
    return model


def _next_model(current):
    pool = _pool_models()
    if not pool:
        return current
    try:
        return pool[(pool.index(current) + 1) % len(pool)]
    except ValueError:
        return pool[0]


def _enforce_pool(model, **_kwargs):
    pool = _pool_models()
    if pool and model and model not in pool:
        picked = pool[_RR["i"] % len(pool)]
        _RR["i"] += 1
        return picked
    return model


def _cmd(task, model=None, resume_id=None):
    template = _template()
    if not template:
        raise ValueError("runtime-not-configured: set HUNT_AGENT_CMD to the active AI command")
    if resume_id and "{resume}" not in template:
        raise ValueError("runtime-resume-unsupported: configured command has no {resume} placeholder")
    values = {"{task}": str(task or ""), "{model}": str(model or ""),
              "{resume}": str(resume_id or "")}
    cmd = []
    for arg in shlex.split(template):
        for key, value in values.items():
            arg = arg.replace(key, value)
        if arg:
            cmd.append(arg)
    if not cmd:
        raise ValueError("runtime-not-configured: empty HUNT_AGENT_CMD")
    for element in cmd:
        if element in _DANGEROUS_FLAGS:
            raise ValueError(f"dangerous agent flag refused: {element}")
    return cmd


def _rate_limited(text):
    low = str(text or "").lower()
    return any(k in low for k in ("rate limit", "usage limit", "quota", "too many requests", "429"))


def _parse_result_json(stdout):
    """Parse a JSON result or result-bearing event stream by content."""
    stdout = (stdout or "").strip().lstrip("\ufeff")
    if not stdout:
        return None
    try:
        obj = json.loads(stdout)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    objects, index = [], 0
    while index < len(stdout):
        while index < len(stdout) and stdout[index] not in "{[":
            index += 1
        if index >= len(stdout):
            break
        try:
            obj, end = decoder.raw_decode(stdout, index)
        except json.JSONDecodeError:
            index += 1
            continue
        if isinstance(obj, dict):
            objects.append(obj)
        index = max(end, index + 1)
    if not objects:
        return None
    for obj in reversed(objects):
        if obj.get("type") == "result" or "result" in obj or "text" in obj:
            return obj
    return objects[-1]


def _parse_stream_json(stdout):
    """Parse JSONL text/finish/error events without assuming their producer."""
    stdout = (stdout or "").strip().lstrip("\ufeff")
    if not stdout:
        return None
    texts, session_id, error_text = [], None, None
    usage = {"input": 0, "output": 0, "reasoning": 0,
             "cache": {"read": 0, "write": 0}, "total": 0, "cost": 0.0}
    finish_reason, finishes, events = None, 0, 0
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
        part = obj.get("part") if isinstance(obj.get("part"), dict) else {}
        if not any(key in obj for key in ("part", "sessionID")):
            continue
        events += 1
        session_id = session_id or obj.get("sessionID") or part.get("sessionID")
        if obj.get("type") == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
        elif part.get("type") == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
        nested = part.get("part") if isinstance(part.get("part"), dict) else None
        if nested and isinstance(nested.get("text"), str):
            texts.append(nested["text"])
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
            error = obj.get("error") or {}
            if isinstance(error, dict):
                data = error.get("data") if isinstance(error.get("data"), dict) else {}
                error_text = data.get("message") or error.get("message") or json.dumps(error)[:500]
            else:
                error_text = str(error)[:500]
    if not events:
        return None
    result = "\n".join(texts).strip()
    complete = bool(finishes and finish_reason not in (None, "tool-calls", "tool_calls"))
    out = {"result": result, "session_id": session_id, "usage": usage,
           "complete": complete, "finish_reason": finish_reason}
    if error_text:
        out.update(is_error=True, error="rate-limited" if _rate_limited(error_text) else "agent-error",
                   error_message=error_text)
        if not result:
            out["result"] = error_text
    return out


def _parse_output(stdout):
    data = _parse_stream_json(stdout) or _parse_result_json(stdout)
    if data is None and (stdout or "").strip():
        data = {"result": stdout.strip(), "complete": True}
    if isinstance(data, dict):
        data = dict(data)
        data.setdefault("complete", True)
        if not data.get("session_id") and data.get("sessionID"):
            data["session_id"] = data["sessionID"]
    return data


def _run_once(cmd, model, timeout, env_extra=None, prompt=None):
    started = time.time()
    env = {**os.environ, **{k: str(v) for k, v in (env_extra or {}).items()}} if env_extra else None
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True, env=env)
    except FileNotFoundError:
        return {"result": "", "error": f"{cmd[0]} not found", "model": model,
                "duration_s": round(time.time() - started, 1)}
    except OSError as exc:
        return {"result": "", "error": f"runtime-start-failed: {exc}", "model": model,
                "duration_s": round(time.time() - started, 1)}
    try:
        stdout, stderr = process.communicate(input=prompt, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except Exception:
                stdout, stderr = "", ""
        data = _parse_output(stdout)
        partial = (data.get("result") or data.get("text") or "") if isinstance(data, dict) else ""
        return {"result": partial or (stdout or stderr or "")[-300:], "partial": True,
                "error": "timeout", "model": model,
                "session_id": data.get("session_id") if isinstance(data, dict) else None,
                "usage": data.get("usage") if isinstance(data, dict) else None,
                "duration_s": round(time.time() - started, 1)}
    duration = round(time.time() - started, 1)
    data = _parse_output(stdout)
    if not data:
        return {"result": (stdout or stderr or "")[-300:], "error": "parse:no-json",
                "model": model, "duration_s": duration}
    result = data.get("result") or data.get("text") or ""
    session_id = data.get("session_id")
    if process.returncode not in (0, None):
        detail = data.get("error_message") or result or (stderr or "")[-300:]
        error = data.get("error") or ("rate-limited" if _rate_limited(detail) else "agent-error")
        return {"result": result or detail, "error": error, "model": data.get("model") or model,
                "session_id": session_id, "usage": data.get("usage"), "duration_s": duration}
    if data.get("is_error") or data.get("subtype") == "error":
        error = data.get("error") or ("rate-limited" if _rate_limited(data.get("error_message") or result)
                                      else "agent-error")
        return {"result": result, "error": error, "model": model, "session_id": session_id,
                "usage": data.get("usage"), "duration_s": duration}
    if not data.get("complete", True):
        return {"result": result, "partial": bool(result), "error": "parse:incomplete-jsonl",
                "model": model, "session_id": session_id, "usage": data.get("usage"),
                "duration_s": duration}
    if _rate_limited(result):
        return {"result": result, "error": "rate-limited", "model": model,
                "session_id": session_id, "usage": data.get("usage"), "duration_s": duration}
    return {"result": result, "error": None, "model": data.get("model") or model,
            "session_id": session_id, "usage": data.get("usage"), "duration_s": duration}


_POOL_LOCK = threading.Lock()
_POOL = {}
POOL_SIZE = int(os.environ.get("HUNT_SESSION_POOL", "3"))
MAX_SESSION_USES = int(os.environ.get("HUNT_SESSION_MAX_USES", "25"))
MAX_SESSION_AGE_MIN = int(os.environ.get("HUNT_SESSION_MAX_AGE_MIN", "360"))


def _slug(value):
    return re.sub(r"[^a-z0-9._-]+", "-", str(value or "").strip().lower()).strip("-") or "unknown"


def _sess_dir(context):
    directory = os.path.join(os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")),
                             "_sessions", _slug(context))
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError:
        pass
    return directory


def _pool_file(context):
    return os.path.join(_sess_dir(context), "state.json")


def _created_file():
    return os.path.join(os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")),
                        "_sessions", "_created.json")


def _register_created(session_id):
    if not session_id:
        return
    path = _created_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with _POOL_LOCK:
            try:
                with open(path) as fh:
                    registry = json.load(fh)
            except Exception:
                registry = {}
            if str(session_id) in registry:
                return
            registry[str(session_id)] = time.time()
            temporary = path + ".tmp"
            with open(temporary, "w") as fh:
                json.dump(registry, fh)
            os.replace(temporary, path)
    except Exception:
        pass


def _load_pool_ids(context):
    try:
        with open(_pool_file(context)) as fh:
            return json.load(fh).get("ids", [])
    except Exception:
        return []


def _load_pool_models(context):
    try:
        with open(_pool_file(context)) as fh:
            models = json.load(fh).get("models", {})
        return models if isinstance(models, dict) else {}
    except Exception:
        return {}


def _load_pool_uses(context):
    try:
        with open(_pool_file(context)) as fh:
            uses = json.load(fh).get("uses", {})
        return uses if isinstance(uses, dict) else {}
    except Exception:
        return {}


def _load_pool_runtime(context):
    try:
        with open(_pool_file(context)) as fh:
            return json.load(fh).get("runtime_id")
    except Exception:
        return None


def _persist_pool(context):
    try:
        with _POOL_LOCK:
            slots = list(_POOL.get(context, []))
            ids = [slot["id"] for slot in slots if slot.get("id")]
            models = {slot["id"]: slot["model"] for slot in slots if slot.get("id") and slot.get("model")}
            uses = {slot["id"]: int(slot.get("uses") or 0) for slot in slots if slot.get("id")}
        path = _pool_file(context)
        temporary = path + ".tmp"
        with open(temporary, "w") as fh:
            json.dump({"context": context, "ids": ids, "models": models, "uses": uses,
                       "runtime_id": _runtime(), "ts": time.time()}, fh)
        os.replace(temporary, path)
    except Exception:
        pass


def _ids_to_retire(orphans, kept):
    return list(dict.fromkeys(session_id for session_id in orphans if session_id and session_id != kept))


def _session_ancient(_session_id):
    return False


def _session_alive(session_id):
    return bool(session_id)


def _retire(_session_id):
    return None


def _retire_all(ids):
    for session_id in ids:
        _retire(session_id)


def _acquire(context):
    retire = []
    chosen = None
    with _POOL_LOCK:
        slots = _POOL.setdefault(context, [])
        if not slots:
            models = _load_pool_models(context)
            uses = _load_pool_uses(context)
            approved = _pool_models()
            same_runtime = _load_pool_runtime(context) == _runtime()
            for session_id in (_load_pool_ids(context) if same_runtime else [])[:POOL_SIZE]:
                used = int(uses.get(session_id) or 0)
                stored_model = models.get(session_id)
                if (used >= MAX_SESSION_USES or (approved and stored_model not in approved)
                        or not runtime_info()["supports_resume"]):
                    retire.append(session_id)
                    continue
                slots.append({"id": session_id, "model": stored_model, "uses": used,
                              "runtime_id": _runtime(), "inuse": False})
        for slot in slots:
            if not slot["inuse"]:
                slot["inuse"] = True
                chosen = slot
                break
        if chosen is None and len(slots) < POOL_SIZE:
            chosen = {"id": None, "model": None, "uses": 0, "runtime_id": _runtime(), "inuse": True}
            slots.append(chosen)
        elif chosen is None:
            chosen = {"id": None, "model": None, "uses": 0, "runtime_id": _runtime(),
                      "inuse": True, "transient": True}
    if retire:
        _persist_pool(context)
        _retire_all(retire)
    return chosen


def _release(slot):
    with _POOL_LOCK:
        slot["inuse"] = False


def session_stats():
    with _POOL_LOCK:
        return {context: len(slots) for context, slots in _POOL.items()}


def run_agent(task, context=None, skills_on=False, model=None, max_turns=40, timeout=600, attempts=2,
              resume_id=None, scope_file=None, env_extra=None):
    """Run only the configured command; never infer a runtime or fallback provider."""
    del skills_on, max_turns
    if scope_file:
        task = f"[scope-file: {scope_file}] — load this scope before acting.\n\n{task}"
    _load_model_env()
    if os.environ.get("HUNT_MOCK_AGENT") == "1":
        selected = _enforce_pool(model or _pick_model())
        error = (os.environ.get("HUNT_MOCK_ERROR") or "").strip() or None
        return {"result": os.environ.get("HUNT_MOCK_RESULT", "```json\n[]\n```"),
                "error": error, "model": selected or "mock", "duration_s": 0.0,
                "reused": bool(resume_id), "session_id": resume_id or "mock-session"}
    if not _template():
        return {"result": "", "error": "runtime-not-configured: set HUNT_AGENT_CMD to the active AI command",
                "model": model, "session_id": resume_id, "duration_s": 0.0}
    prompt = task if "{task}" not in _template() else None
    if resume_id:
        selected = _enforce_pool(model)
        try:
            cmd = _cmd(task, selected, resume_id=resume_id)
        except ValueError as exc:
            return {"result": str(exc), "error": "runtime-resume-unsupported", "model": selected,
                    "session_id": resume_id, "reused": True, "duration_s": 0.0}
        result = _run_once(cmd, selected, timeout, env_extra=env_extra, prompt=prompt)
        result.setdefault("model", selected)
        result["reused"] = True
        _register_created(result.get("session_id") or resume_id)
        return result

    ephemeral = context is None
    slot = _acquire(context) if not ephemeral else {"id": None, "model": None, "uses": 0, "ephemeral": True}
    orphans = []
    try:
        approved = _pool_models()
        reuse = bool(slot.get("id") and slot["uses"] < MAX_SESSION_USES and not model
                     and not slot.get("transient") and not ephemeral and runtime_info()["supports_resume"]
                     and slot.get("runtime_id") == _runtime())
        if reuse and approved and slot.get("model") not in approved:
            orphans.append(slot["id"])
            slot.update(id=None, model=None, uses=0)
            reuse = False
        if reuse:
            selected, cmd = slot["model"], _cmd(task, slot["model"], resume_id=slot["id"])
        else:
            if slot.get("id"):
                orphans.append(slot["id"])
            selected = _enforce_pool(model or _pick_model())
            slot.update(id=None, model=selected, uses=0, runtime_id=_runtime())
            cmd = _cmd(task, selected)
        result = {}
        for attempt in range(1, max(1, attempts) + 1):
            result = _run_once(cmd, selected, timeout, env_extra=env_extra, prompt=prompt)
            if result.get("session_id") and runtime_info()["supports_resume"]:
                if slot.get("id") and slot["id"] != result["session_id"]:
                    orphans.append(slot["id"])
                slot["id"] = result["session_id"]
                _register_created(result["session_id"])
            if result.get("model") and not slot.get("model"):
                slot["model"] = result["model"]
            if result.get("error") not in _RETRYABLE or attempt >= attempts:
                break
            time.sleep(2 * attempt)
            result["retried"] = attempt
            if slot.get("id"):
                orphans.append(slot["id"])
            slot["id"] = None
            selected = _next_model(selected)
            slot["model"] = selected
            result["failover_model"] = selected
            cmd = _cmd(task, selected)
        if result.get("error"):
            if slot.get("id"):
                orphans.append(slot["id"])
            slot.update(id=None, model=None, uses=0)
        else:
            slot["uses"] = int(slot.get("uses") or 0) + 1
        if ephemeral or slot.get("transient") or not runtime_info()["supports_resume"]:
            if slot.get("id"):
                orphans.append(slot["id"])
            slot["id"] = None
        if context is not None and not slot.get("transient"):
            _persist_pool(context)
        _retire_all(_ids_to_retire(orphans, slot.get("id")))
        result.setdefault("model", selected)
        result["reused"] = reuse
        result["runtime_id"] = _runtime()
        return result
    finally:
        if context is not None and not slot.get("transient"):
            _release(slot)


def extract_json(text):
    """Pull the last valid JSON array/object out of an agent reply."""
    if not text:
        return None
    blocks = re.findall(r"```json\s*(.*?)```", text, re.S)
    blocks += re.findall(r"```\s*(\[.*?\]|\{.*?\})\s*```", text, re.S)
    for block in reversed(blocks):
        try:
            return json.loads(block.strip())
        except Exception:
            pass
    for block in reversed(re.findall(r"(\[.*\]|\{.*\})", text, re.S)):
        try:
            return json.loads(block)
        except Exception:
            pass
    return None


if __name__ == "__main__":
    assert extract_json('blah ```json\n[{"a":1}]\n``` end') == [{"a": 1}]
    assert _parse_result_json('{"type":"result","is_error":false,"result":"PONG"}')["result"] == "PONG"
    assert _parse_output("plain response")["result"] == "plain response"
    stream = ('{"type":"step_start","sessionID":"generic-1"}\n'
              '{"type":"text","sessionID":"generic-1","part":{"type":"text","text":"PONG"}}\n'
              '{"type":"step_finish","sessionID":"generic-1","part":{"reason":"stop","tokens":{"input":2,"output":1}}}')
    parsed = _parse_output(stream)
    assert parsed["result"] == "PONG" and parsed["complete"] and parsed["session_id"] == "generic-1"
    previous = os.environ.get("HUNT_AGENT_CMD")
    os.environ["HUNT_AGENT_CMD"] = "/bin/cat"
    try:
        command = _cmd("hello", "arbitrary-label")
        result = _run_once(command, "arbitrary-label", 2, prompt="hello")
        assert result["result"] == "hello" and not result["error"], result
        assert _runtime() != "unconfigured"
    finally:
        if previous is None:
            os.environ.pop("HUNT_AGENT_CMD", None)
        else:
            os.environ["HUNT_AGENT_CMD"] = previous
    print("agent.py generic-runtime self-test: PASS")
