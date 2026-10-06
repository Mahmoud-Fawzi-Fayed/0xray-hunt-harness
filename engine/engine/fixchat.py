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
import sys
import time
import uuid

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
MSG_TIMEOUT = int(os.environ.get("HUNT_FIXCHAT_TIMEOUT", "420"))


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "adhoc"


def _chat_id_ok(cid):
    return bool(re.fullmatch(r"[a-f0-9-]{36}", str(cid or "")))


def _dir(base, program, cid):
    return os.path.realpath(os.path.join(os.path.expanduser(base), _slug(program),
                                         "verify-fixchat", cid))


def _meta_path(root):
    return os.path.join(root, ".fixchat.json")


def _load_meta(root):
    try:
        return json.load(open(_meta_path(root)))
    except Exception:  # noqa: BLE001
        return None


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
    return (
        "You are a bug-bounty REPORT FIXER. The operator's draft report failed the verification gate. "
        f"The uploaded report + evidence files are in: {root} — you may READ and EDIT files in THIS "
        "directory ONLY (never touch anything outside it). Your job: fix the report so it passes — "
        "rewrite/add sections IN the report file(s): clear numbered repro steps, a PoC section with the "
        "raw request/response, a concrete impact statement, honest severity. Never invent evidence the "
        "operator didn't provide — if proof is missing, add a clearly-marked 'TODO(operator):' line "
        "saying exactly what to capture, instead of fabricating it. Redact any real PII/secrets.\n\n"
        f"VERIFY VERDICT: {(verify_res or {}).get('verdict', '?')}\n"
        f"FAILED CHECKS + WHAT TO ADD:\n{fixes}\n\n"
        f"FINDING CONTEXT:\n{json.dumps({k: v for k, v in (finding or {}).items() if not k.startswith('_')}, indent=2)[:4000]}\n\n"
        "Start by reading the report file(s), then make the fixes. Reply with a short summary of what "
        "you changed and what the operator still needs to capture.")


def start(program, finding, files, verify_res, base=DEFAULT_BASE, model=None):
    """Open a fix chat: save the uploads, start a fresh agent session, return {chat_id, reply, files}."""
    import agent as A
    cid = str(uuid.uuid4())
    root = _dir(base, program, cid)
    os.makedirs(root, exist_ok=True)
    os.chmod(root, 0o700)
    saved, rejected = _save_files(files, root)
    task = _task_start(root, finding, verify_res)
    r = A.run_agent(task, context=None, model=model, timeout=MSG_TIMEOUT, attempts=1)
    meta = {"chat_id": cid, "program": _slug(program), "session_id": r.get("session_id"),
            "model": r.get("model"), "created": time.time(),
            "verdict": (verify_res or {}).get("verdict")}
    json.dump(meta, open(_meta_path(root), "w"))
    os.chmod(_meta_path(root), 0o600)
    return {"chat_id": cid, "reply": r.get("result") or r.get("error") or "(no reply)",
            "error": r.get("error"), "files": _listing(root),
            "saved": saved, "rejected": rejected}


def message(cid, text, base=DEFAULT_BASE, program=None):
    """Send a follow-up: resumes the SAME agent session so it remembers the report + prior edits."""
    import agent as A
    if not _chat_id_ok(cid):
        return {"error": "bad chat id"}
    # find the dir across programs (chat_id is unique; locate via glob)
    import glob
    hits = glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", cid))
    root = os.path.realpath(hits[0]) if hits else None
    if not root or not os.path.isdir(root):
        return {"error": "chat not found (closed or expired)"}
    meta = _load_meta(root) or {}
    task = (str(text or "")[:8000] +
            f"\n\n(Reminder: the files are in {root} — edit them in place, this directory only. "
            "Reply with a short summary of changes.)")
    r = A.run_agent(task, context=None, resume_id=meta.get("session_id"),
                    model=meta.get("model"), timeout=MSG_TIMEOUT, attempts=1)
    if r.get("session_id"):
        meta["session_id"] = r["session_id"]
        json.dump(meta, open(_meta_path(root), "w"))
    return {"reply": r.get("result") or r.get("error") or "(no reply)", "error": r.get("error"),
            "files": _listing(root)}


def read_file(cid, name, base=DEFAULT_BASE):
    """Bytes of one file in the chat dir (download). Basename-only, must resolve inside the dir."""
    import glob
    import verify as V
    if not _chat_id_ok(cid):
        return None, None
    hits = glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", cid))
    if not hits:
        return None, None
    root = os.path.realpath(hits[0])
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
    import glob
    import shutil
    if not _chat_id_ok(cid):
        return {"error": "bad chat id"}
    hits = glob.glob(os.path.join(os.path.expanduser(base), "*", "verify-fixchat", cid))
    root = os.path.realpath(hits[0]) if hits else None
    if not root or not os.path.isdir(root):
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
        c = close(cid, base=base)
        assert c["closed"] and c["dir_removed"], c
        assert message(cid, "hi", base=base).get("error"), "closed chat must be gone"
        assert close("not-a-uuid", base=base).get("error")
    finally:
        os.environ.pop("HUNT_MOCK_AGENT", None)
        os.environ.pop("HUNT_MOCK_RESULT", None)
    print("fixchat.py self-test: PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(_selftest())
    print(__doc__)
