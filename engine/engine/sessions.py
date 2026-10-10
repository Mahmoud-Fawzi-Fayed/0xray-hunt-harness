#!/usr/bin/env python3
"""
sessions.py — GUARDED session management. Nothing is ever deleted automatically; removal requires an
explicit --confirm. This is the only sanctioned way to clear sessions (the "restrict removal to one
solution" control).

cursor-agent keeps a session in TWO on-disk stores — both are managed here:
  - chat dirs:        ~/.cursor/chats/<workspace-hash>/<session-id>/          (IDE + agent state)
  - agent transcripts: ~/.cursor/projects/<workspace-slug>/agent-transcripts/<session-id>/  (headless runs)
A session is ALIVE only if its id exists on disk; a pooled id with no dir is DEAD (cursor-agent
--resume on a dead id silently starts a zero-context session — the "lost connection" symptom).

Plus the per-target hunt pools: <base>/_sessions/<slug>/state.json  (active hunts resume these).

Safety rules (enforced in code):
  * DRY-RUN by default — prints what WOULD be removed; deletes only with --confirm.
  * NEVER removes a session id that is in ANY target's pool (live hunts keep working).
  * NEVER touches UNMANAGED workspaces (e.g. the operator's interactive `root` project, CTFs):
    only transcript stores matching HUNT_SESSION_STORES are managed; the rest are report-only.
  * In the chats store, bulk clear removes only EMPTY dirs/husks — non-empty IDE chats are left alone.
  * --reset <slug> clears that target's pool + its sessions (only when the target is not running).

CLI:
  python3 sessions.py list                       # inventory: sessions on disk, pools, orphans, health
  python3 sessions.py doctor                     # DRY-RUN: dead pooled ids / corrupt pools that WOULD heal
  python3 sessions.py doctor --confirm           # heal: drop dead ids from non-running pools
  python3 sessions.py clear --all                # DRY-RUN: orphaned sessions that would be removed
  python3 sessions.py clear --all --confirm      # actually remove orphaned sessions
  python3 sessions.py reset --slug wyylde --confirm   # reset one target's session pool + sessions
"""
import argparse
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def _chats_dir():
    return os.environ.get("HUNT_CHATS_DIR", os.path.expanduser("~/.cursor/chats"))


def _projects_dir():
    return os.environ.get("HUNT_PROJECTS_DIR", os.path.expanduser("~/.cursor/projects"))


def _managed_pats():
    """Which transcript workspaces the harness manages (its own hunts) — everything else is hands-off."""
    return [p.strip() for p in os.environ.get(
        "HUNT_SESSION_STORES", "root-Claude-BugHunter*,root-BugHunting-0xRay*").split(",") if p.strip()]


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


def _pools(base):
    """{slug: [session ids]} from <base>/_sessions/*/state.json. Unreadable files -> None (corrupt)."""
    out = {}
    for f in glob.glob(os.path.join(os.path.expanduser(base), "_sessions", "*", "state.json")):
        slug = os.path.basename(os.path.dirname(f))
        try:
            ids = json.load(open(f)).get("ids", [])
            out[slug] = [str(x) for x in ids] if isinstance(ids, list) else None
        except Exception:  # noqa: BLE001
            out[slug] = None                       # corrupt state.json — doctor handles it
    return out


def _running_slugs():
    """Slugs whose hunt-<slug> pm2 process is online (their sessions must never be removed)."""
    try:
        r = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=15)
        procs = json.loads(r.stdout or "[]")
        return {p["name"][5:] for p in procs
                if p.get("name", "").startswith("hunt-") and p["name"] != "hunt-bridge"
                and (p.get("pm2_env", {}) or {}).get("status") == "online"}
    except Exception:  # noqa: BLE001
        return set()


def _managed_stores():
    """Transcript dirs the harness manages (its own hunt workspaces) -> {workspace: dir}."""
    out = {}
    for d in glob.glob(os.path.join(_projects_dir(), "*", "agent-transcripts")):
        ws = os.path.basename(os.path.dirname(d))
        if any(fnmatch.fnmatch(ws, pat) for pat in _managed_pats()):
            out[ws] = d
    return out


def _chat_session_dirs():
    """All chats-store session dirs (~/.cursor/chats/<hash>/<id>)."""
    return [d for d in glob.glob(os.path.join(_chats_dir(), "*", "*")) if os.path.isdir(d)]


def _transcript_session_dirs(managed_only=True):
    """{session_id: dir} across managed transcript stores (or ALL stores if managed_only=False)."""
    out = {}
    stores = _managed_stores().values() if managed_only else \
        glob.glob(os.path.join(_projects_dir(), "*", "agent-transcripts"))
    for store in stores:
        for d in glob.glob(os.path.join(store, "*")):
            if os.path.isdir(d):
                out.setdefault(os.path.basename(d), d)
    return out


def session_dirs(sid):
    """Every on-disk dir for a session id, across BOTH stores and ALL workspaces."""
    sid = re.sub(r"[^A-Za-z0-9._-]", "", str(sid or ""))
    if not sid:
        return []
    dirs = [d for d in glob.glob(os.path.join(_chats_dir(), "*", sid)) if os.path.isdir(d)]
    dirs += [d for d in glob.glob(os.path.join(_projects_dir(), "*", "agent-transcripts", sid)) if os.path.isdir(d)]
    return dirs


def is_alive(sid):
    """A session is alive iff its id exists on disk in any store (resume of a dead id silently
    restarts with zero context — so existence is the ONLY reliable liveness signal)."""
    return bool(session_dirs(sid))


def inventory(base=DEFAULT_BASE):
    pools = _pools(base)
    running = _running_slugs()
    pooled_ids = {i for ids in pools.values() for i in (ids or [])}
    chats = _chat_session_dirs()
    empty_chats = [d for d in chats if not os.listdir(d)]
    transcripts = _transcript_session_dirs(managed_only=True)
    t_orphans = {i: d for i, d in transcripts.items() if i not in pooled_ids}
    husks = [d for d in glob.glob(os.path.join(_chats_dir(), "*")) if os.path.isdir(d) and not os.listdir(d)]
    health = {slug: ({"corrupt": True} if ids is None else
                     {"ids": ids, "dead": [i for i in ids if not is_alive(i)],
                      "alive": [i for i in ids if is_alive(i)]})
              for slug, ids in pools.items()}
    return {"pools": pools, "running": sorted(running), "pooled_ids": pooled_ids,
            "chats": chats, "empty_chats": empty_chats, "husks": husks,
            "transcripts": transcripts, "transcript_orphans": t_orphans,
            "orphans": [d for d in chats if os.path.basename(d) not in pooled_ids],  # legacy view
            "pool_health": health}


def doctor(base=DEFAULT_BASE, confirm=False):
    """Check every pool: dead ids (no on-disk session) + corrupt state.json. With confirm, HEAL:
    drop dead ids from NON-running pools (a running hunt drops a dead id itself on its next step,
    via the agent.py liveness guard) and quarantine corrupt state files. Never touches running pools."""
    inv = inventory(base)
    out = {"dry_run": not confirm, "pools": {}, "healed": [], "quarantined": [], "running_skipped": []}
    for slug, h in inv["pool_health"].items():
        running = slug in inv["running"]
        if h.get("corrupt"):
            out["pools"][slug] = {"corrupt": True, "running": running}
            if running:
                out["running_skipped"].append(slug)
            elif confirm:
                pf = os.path.join(os.path.expanduser(base), "_sessions", slug, "state.json")
                try:
                    os.replace(pf, pf + ".corrupt-bak")
                    json.dump({"context": slug, "ids": [], "ts": 0, "model": None}, open(pf, "w"))
                    out["quarantined"].append(slug)
                except OSError:
                    pass
            continue
        dead, alive = h["dead"], h["alive"]
        out["pools"][slug] = {"alive": len(alive), "dead": dead, "running": running}
        if not dead:
            continue
        if running:
            out["running_skipped"].append(slug)     # engine self-heals on its next step
        elif confirm:
            pf = os.path.join(os.path.expanduser(base), "_sessions", slug, "state.json")
            try:
                st = json.load(open(pf))
                st["ids"] = [i for i in st.get("ids", []) if i in set(alive)]
                tmp = pf + ".tmp"
                json.dump(st, open(tmp, "w"))
                os.replace(tmp, pf)
                out["healed"].append({"slug": slug, "dropped": dead})
            except OSError:
                pass
    return out


def clear_orphans(base=DEFAULT_BASE, confirm=False):
    """Remove sessions no pool references: HARNESS-CREATED orphan transcripts + empty chat dirs + empty
    workspace husks. Transcript removal is gated on the created-id registry, so the operator's
    interactive/IDE transcripts (never registered) are NEVER removed — even though their workspace may
    match the managed pattern. With no registry yet, only empty husks/dirs are cleaned (fail-safe).
    Non-empty unmanaged/IDE chats are never touched."""
    inv = inventory(base)
    reg = created_ids(base)
    if reg:
        t_orphans = [d for sid, d in inv["transcript_orphans"].items() if sid in reg]
    else:
        t_orphans = []                 # no registry -> don't risk operator transcripts; husks/empty only
    targets = t_orphans + inv["empty_chats"] + inv["husks"]
    out = {"orphans_found": len(targets), "removed": 0, "skipped_pooled": 0, "dry_run": not confirm,
           "by_kind": {"transcripts": len(t_orphans),
                       "empty_chat_dirs": len(inv["empty_chats"]), "husks": len(inv["husks"])}}
    for d in targets:
        if os.path.basename(d) in inv["pooled_ids"]:
            out["skipped_pooled"] += 1
            continue
        if confirm:
            try:
                shutil.rmtree(d)
                out["removed"] += 1
            except OSError:
                pass
    return out


def drop_ids(ids, base=DEFAULT_BASE):
    """Remove SPECIFIC sessions by id, across BOTH stores and ALL workspaces — used to clean up
    ephemeral one-shot sessions (e.g. verify triager runs) right after they finish. Safety: an id
    that is in ANY target's pool is never removed, so a live hunt can never lose a session to this."""
    pooled = {i for ids_ in _pools(base).values() for i in (ids_ or [])}
    removed, skipped = 0, 0
    for sid in (ids or []):
        sid = re.sub(r"[^A-Za-z0-9._-]", "", str(sid or ""))
        if not sid:
            continue
        if sid in pooled:
            skipped += 1
            continue
        for cdir in session_dirs(sid):
            try:
                shutil.rmtree(cdir)
                removed += 1
            except OSError:
                pass
    return {"removed": removed, "skipped_pooled": skipped}


def created_ids(base=DEFAULT_BASE):
    """Session ids the HUNTING HARNESS created (recorded by agent.py as it mints them in
    <base>/_sessions/_created.json). The operator's interactive/IDE sessions are NEVER recorded here
    — which is exactly what lets automated cleanup target harness sessions only. Empty set until the
    hunts have run under the registry-aware agent (safe: an empty registry prunes nothing)."""
    p = os.path.join(os.path.expanduser(base), "_sessions", "_created.json")
    try:
        reg = json.load(open(p))
        return {str(k) for k in reg} if isinstance(reg, dict) else set()
    except Exception:  # noqa: BLE001
        return set()


def _engine_cwds():
    """Working directories cursor-agent is launched from by the panel/harness. Operator chats use
    other directories and are never matched by this list."""
    raw = os.environ.get(
        "HUNT_ENGINE_CWDS",
        "/root/Claude-BugHunter,/root/Claude-BugHunter/engine,/root/.claude/skills")
    return {os.path.realpath(p.strip()) for p in raw.split(",") if p.strip()}


def _chat_meta(path):
    try:
        with open(os.path.join(path, "meta.json")) as fh:
            m = json.load(fh)
        return m if isinstance(m, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _conversation_ts(sid):
    """Last conversation update (meta.updatedAtMs). Directory mtime is ignored: opening the store
    rewrites it and would make a finished session look active."""
    stamps, mtimes = [], []
    for d in session_dirs(sid):
        ms = _chat_meta(d).get("updatedAtMs")
        if ms:
            stamps.append(float(ms) / 1000.0)
        try:
            mtimes.append(os.path.getmtime(d))
        except OSError:
            pass
    if stamps:
        return max(stamps)                 # conversation time wins over a touched folder
    return max(mtimes) if mtimes else None


def engine_session_ids():
    """Panel/harness sessions that never landed in the created-id registry: untitled chats whose
    cwd is an engine launch directory, and subagents in a workspace that has no operator chat.
    A titled chat is never returned. A workspace that holds an operator chat (a title, or a cwd
    outside the engine list) keeps its subagents — those belong to that chat."""
    cwds = _engine_cwds()
    by_ws = {}
    for d in _chat_session_dirs():
        by_ws.setdefault(os.path.dirname(d), []).append(d)
    ids = []
    for dirs in by_ws.values():
        metas = [(d, _chat_meta(d)) for d in dirs]
        operator = False
        for _, m in metas:
            cwd = m.get("cwd") or ""
            try:
                engine = bool(cwd) and os.path.realpath(cwd) in cwds
            except Exception:  # noqa: BLE001
                engine = False
            if m.get("title") or (cwd and not engine and not m.get("isSubagent")):
                operator = True
                break
        for d, m in metas:
            if m.get("title"):
                continue
            cwd = m.get("cwd") or ""
            try:
                engine = bool(cwd) and os.path.realpath(cwd) in cwds
            except Exception:  # noqa: BLE001
                engine = False
            if engine or (m.get("isSubagent") and not operator):
                ids.append(os.path.basename(d))
    return ids


# Spawned hunt/subagent prompts. These are what fill /resume. A chat the operator typed
# ("what is the status", "start hunting on ...") does not match.
_SPAWNED_HEAD = re.compile(
    r"^(you are\b|authorized\b|expert bug bounty\b|reply with exactly\b|"
    r"rules of engagement\b|pentest this one endpoint\b)",
    re.I)


def _opening_head(text):
    m = re.search(r"<user_query>\s*(.{0,500})", text or "", re.S)
    head = (m.group(1) if m else "").split("</user_query>")[0]
    # jsonl stores newlines as the two characters "\n" inside the JSON string
    return head.replace("\\n", "\n").replace("\\t", "\t").strip()


def _is_spawned_prompt(text):
    return bool(_SPAWNED_HEAD.match(_opening_head(text)))


def _operator_chat_ids():
    """Chats the operator opened in the IDE: titled, or a non-engine cwd that is not a subagent.
    Spawned hunt prompts never qualify, so they can be removed from /resume."""
    ids = set()
    cwds = _engine_cwds()
    for d in _chat_session_dirs():
        m = _chat_meta(d)
        if m.get("title"):
            ids.add(os.path.basename(d))
            continue
        cwd = m.get("cwd") or ""
        try:
            engine = bool(cwd) and os.path.realpath(cwd) in cwds
        except Exception:  # noqa: BLE001
            engine = False
        if cwd and not engine and not m.get("isSubagent"):
            ids.add(os.path.basename(d))
    return ids


def sweep_spawned_sessions(base=DEFAULT_BASE, confirm=False):
    """Remove resume transcripts whose opening prompt is a spawned hunt/subagent/CTF-solver
    template. The operator's own chats (a title, or any non-engine cwd) are never selected,
    and neither is a session a live agent is resuming or a running hunt still has pooled."""
    protect = _operator_chat_ids() | live_resume_ids()
    protect |= {i for ids in _pools(base).values() for i in (ids or [])}
    found = []
    for store in glob.glob(os.path.join(_projects_dir(), "*", "agent-transcripts")):
        for d in glob.glob(os.path.join(store, "*")):
            if not os.path.isdir(d):
                continue
            sid = os.path.basename(d)
            if sid in protect:
                continue
            jl = os.path.join(d, sid + ".jsonl")
            try:
                with open(jl, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(20000)
            except OSError:
                continue
            if _is_spawned_prompt(head):
                found.append(sid)
    found = list(dict.fromkeys(found))
    removed = 0
    if confirm and found:
        removed = drop_ids(found, base=base).get("removed", 0)
    return {"found": len(found), "removed": removed, "dry_run": not confirm}


def live_resume_ids():
    """Session ids a cursor-agent process is actually resuming right now. Anything else on disk
    is not a running hunt, even if its folder was touched recently."""
    try:
        r = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True, timeout=10)
        return set(re.findall(r"--resume\s+([0-9A-Fa-f-]{36})", r.stdout or ""))
    except Exception:  # noqa: BLE001
        return set()


def clear_harness(base=DEFAULT_BASE, stale_min=30, confirm=False):
    """Remove harness sessions that are BOTH (a) not in any target's active pool and (b) stale —
    the conversation itself has not updated within `stale_min` minutes. Sources: the created-id
    registry, plus untitled engine-cwd chats and hunt subagents (engine_session_ids).

    The operator's titled chats, and subagents sitting in a workspace that has an operator chat,
    are never selected. Dry-run unless confirm=True."""
    inv = inventory(base)
    reg = created_ids(base)
    pooled = inv["pooled_ids"]
    live = live_resume_ids()
    cutoff = time.time() - max(0, stale_min) * 60
    victims = []
    for sid in set(reg) | set(engine_session_ids()):
        if sid in pooled or sid in live:
            continue                               # reused by a target, or a process is resuming it now
        if not session_dirs(sid):
            continue                               # already gone
        ts = _conversation_ts(sid)
        if ts is None or ts >= cutoff:
            continue                               # no conversation stamp, or still active
        victims.append(sid)
    out = {"registry": len(reg), "candidates": len(victims), "removed": 0, "skipped_pooled": 0,
           "dry_run": not confirm}
    if confirm and victims:
        r = drop_ids(victims, base=base)           # removes both stores; skips any pooled id
        out["removed"] = r["removed"]
        out["skipped_pooled"] = r["skipped_pooled"]
    spawned = sweep_spawned_sessions(base=base, confirm=confirm)
    out["spawned"] = spawned["found"]
    if confirm:
        out["removed"] += spawned["removed"]
    return out


def reset_target(slug, base=DEFAULT_BASE, confirm=False):
    slug = _slug(slug)
    inv = inventory(base)
    if slug in inv["running"]:
        return {"error": f"'{slug}' is RUNNING — stop it first (pm2 stop hunt-{slug}) before resetting its sessions"}
    ids = inv["pools"].get(slug) or []
    out = {"slug": slug, "pool_ids": ids, "sessions_removed": 0, "pool_cleared": False, "dry_run": not confirm}
    if not confirm:
        return out
    for sid in ids:
        for cdir in session_dirs(sid):
            try:
                shutil.rmtree(cdir)
                out["sessions_removed"] += 1
            except OSError:
                pass
    pf = os.path.join(os.path.expanduser(base), "_sessions", slug, "state.json")
    try:
        if os.path.isfile(pf):
            json.dump({"ids": []}, open(pf, "w"))
        out["pool_cleared"] = True
    except OSError:
        pass
    return out


def _main(argv=None):
    ap = argparse.ArgumentParser(description="guarded session management (dry-run unless --confirm)")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    pd = sub.add_parser("doctor"); pd.add_argument("--confirm", action="store_true")
    pc = sub.add_parser("clear"); pc.add_argument("--all", action="store_true"); pc.add_argument("--confirm", action="store_true")
    pr = sub.add_parser("reset"); pr.add_argument("--slug", required=True); pr.add_argument("--confirm", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    if a.cmd == "list":
        inv = inventory(a.base)
        print(f"chat session dirs      : {len(inv['chats'])} ({len(inv['empty_chats'])} empty, {len(inv['husks'])} workspace husks)")
        print(f"hunt transcripts (managed stores): {len(inv['transcripts'])}")
        print(f"orphaned transcripts   : {len(inv['transcript_orphans'])} (safe to clear)")
        print(f"pooled session ids     : {len(inv['pooled_ids'])}")
        print(f"running hunts          : {', '.join(inv['running']) or '(none)'}")
        for s, h in inv["pool_health"].items():
            if h.get("corrupt"):
                print(f"  pool {s}: CORRUPT state.json")
            else:
                tag = " [RUNNING — protected]" if s in inv["running"] else ""
                dead = f" · DEAD: {len(h['dead'])}" if h["dead"] else ""
                print(f"  pool {s}: {len(h['alive'])} alive{dead}{tag}")
        return 0
    if a.cmd == "doctor":
        r = doctor(a.base, confirm=a.confirm)
        tag = "HEALED" if a.confirm else "DRY-RUN"
        print(json.dumps(r, indent=2))
        if not a.confirm:
            print(f"({tag}: re-run with --confirm to drop dead ids from non-running pools)")
        return 0
    if a.cmd == "clear":
        r = clear_orphans(a.base, confirm=a.confirm)
        tag = "REMOVED" if a.confirm else "DRY-RUN (would remove)"
        print(f"{tag} {r['removed'] if a.confirm else r['orphans_found']} orphaned session(s) "
              f"({', '.join(f'{k}={v}' for k, v in r['by_kind'].items())}); "
              f"skipped {r['skipped_pooled']} pooled. " + ("" if a.confirm else "Re-run with --confirm to delete."))
        return 0
    if a.cmd == "reset":
        r = reset_target(a.slug, a.base, confirm=a.confirm)
        if r.get("error"):
            print("ERROR:", r["error"], file=sys.stderr); return 1
        print(("DRY-RUN would reset" if not a.confirm else "reset") + f" {r['slug']}: "
              f"{len(r['pool_ids'])} pool session(s), {r['sessions_removed']} session dir(s) removed. "
              + ("" if a.confirm else "Re-run with --confirm."))
        return 0


def _selftest():
    import tempfile
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "_sessions", "acme"))
    os.makedirs(os.path.join(base, "_sessions", "broken"))
    json.dump({"ids": ["s1", "s2", "dead1"]}, open(os.path.join(base, "_sessions", "acme", "state.json"), "w"))
    open(os.path.join(base, "_sessions", "broken", "state.json"), "w").write("{not json")
    # fake stores via env overrides
    chats = tempfile.mkdtemp()
    projects = tempfile.mkdtemp()
    os.environ["HUNT_CHATS_DIR"] = chats
    os.environ["HUNT_PROJECTS_DIR"] = projects
    os.environ["HUNT_SESSION_STORES"] = "hunt-*"
    tstore = os.path.join(projects, "hunt-target", "agent-transcripts")
    os.makedirs(os.path.join(tstore, "s1"))                       # alive pooled
    os.makedirs(os.path.join(tstore, "s2"))                       # alive pooled
    os.makedirs(os.path.join(tstore, "orphan1"))                  # orphan transcript
    os.makedirs(os.path.join(projects, "root", "agent-transcripts", "ide-chat"))   # UNMANAGED ws
    os.makedirs(os.path.join(chats, "wshash", "s1"))              # alive pooled (chats store)
    os.makedirs(os.path.join(chats, "wshash", "emptychat"))       # empty chat dir -> husk-ish
    os.makedirs(os.path.join(chats, "emptyws"))                   # workspace husk
    try:
        pools = _pools(base)
        assert pools["acme"] == ["s1", "s2", "dead1"] and pools["broken"] is None, pools
        assert is_alive("s1") and not is_alive("dead1"), "liveness"
        inv = inventory(base)
        assert "orphan1" in inv["transcript_orphans"] and "s1" not in inv["transcript_orphans"]
        assert "ide-chat" not in inv["transcripts"], "unmanaged workspace must not be managed"
        # dry-run never deletes / never heals
        r = clear_orphans(base, confirm=False)
        assert r["dry_run"] is True and r["removed"] == 0, r
        d = doctor(base, confirm=False)
        assert d["pools"]["acme"]["dead"] == ["dead1"] and not d["healed"], d
        # confirm: heal drops the dead id, quarantines the corrupt pool, clears orphans
        d = doctor(base, confirm=True)
        assert d["healed"] == [{"slug": "acme", "dropped": ["dead1"]}], d
        assert d["quarantined"] == ["broken"], d
        assert json.load(open(os.path.join(base, "_sessions", "acme", "state.json")))["ids"] == ["s1", "s2"]
        # clear_orphans: transcript removal is gated on the created-id registry (operator transcripts safe)
        json.dump({"orphan1": 0}, open(os.path.join(base, "_sessions", "_created.json"), "w"))  # harness-made
        os.makedirs(os.path.join(tstore, "orphan2"))     # NOT registered (operator) -> must survive
        r = clear_orphans(base, confirm=True)
        assert r["removed"] >= 3, r                       # orphan1 (registered) + emptychat + emptyws husk
        assert not session_dirs("orphan1"), "registered harness orphan must be removed"
        assert is_alive("orphan2"), "unregistered (operator) transcript orphan must survive"
        assert is_alive("s1"), "pooled session must survive"
        assert os.path.isdir(os.path.join(projects, "root", "agent-transcripts", "ide-chat")), "unmanaged untouched"
        # drop_ids removes from BOTH stores but never a pooled id
        os.makedirs(os.path.join(tstore, "tmp1"))
        os.makedirs(os.path.join(chats, "wshash", "tmp1"))
        r = drop_ids(["tmp1", "s1"], base=base)
        assert r["removed"] == 2 and r["skipped_pooled"] == 1, r
        assert not session_dirs("tmp1") and is_alive("s1")
        # clear_harness: removes ONLY registry (harness-created) sessions — never user/IDE sessions
        os.makedirs(os.path.join(chats, "wshash", "hx"))         # harness-created, NOT pooled
        os.makedirs(os.path.join(chats, "wshash", "ux"))         # operator session, NOT in registry
        old = time.time() - 9999
        os.utime(os.path.join(chats, "wshash", "hx"), (old, old))
        os.utime(os.path.join(chats, "wshash", "ux"), (old, old))
        json.dump({"hx": old, "s1": old}, open(os.path.join(base, "_sessions", "_created.json"), "w"))
        assert created_ids(base) == {"hx", "s1"}, created_ids(base)
        rh = clear_harness(base, stale_min=0, confirm=True)
        assert rh["removed"] == 1, rh                            # only hx
        assert not session_dirs("hx"), "harness orphan must be removed"
        assert is_alive("ux"), "operator session (not in registry) must survive"
        assert is_alive("s1"), "pooled harness session must survive"
        # engine-cwd chats + hunt subagents go; titled chats and operator workspaces stay
        eng = "/opt/hunt-engine"
        os.environ["HUNT_ENGINE_CWDS"] = eng
        old_ms = int((time.time() - 9999) * 1000)

        def _meta(path, **kw):
            os.makedirs(path, exist_ok=True)
            json.dump({"updatedAtMs": old_ms, **kw}, open(os.path.join(path, "meta.json"), "w"))

        _meta(os.path.join(chats, "engws", "eng1"), cwd=eng)
        _meta(os.path.join(chats, "engws", "titled"), cwd=eng, title="Keep me")
        _meta(os.path.join(chats, "subws", "sub1"), isSubagent=True)
        _meta(os.path.join(chats, "userws", "mine"), cwd="/home/operator", title="My chat")
        _meta(os.path.join(chats, "userws", "usersub"), isSubagent=True)
        rh2 = clear_harness(base, stale_min=30, confirm=True)
        assert rh2["removed"] >= 2, rh2
        assert not session_dirs("eng1"), "finished engine chat must be removed"
        assert not session_dirs("sub1"), "hunt subagent in an engine-only workspace must be removed"
        assert is_alive("titled"), "titled chat must survive even on an engine cwd"
        assert is_alive("mine") and is_alive("usersub"), "operator workspace and its subagents must survive"
        # /resume clutter: spawned prompts go, a chat the operator typed stays
        spawned = os.path.join(projects, "root", "agent-transcripts", "spawn1")
        human = os.path.join(projects, "root", "agent-transcripts", "human1")
        os.makedirs(spawned); os.makedirs(human)
        open(os.path.join(spawned, "spawn1.jsonl"), "w").write(
            '{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\\nYou are a vuln-hunter subagent in an authorized bug-bounty hunt.\\n</user_query>"}]}}')
        open(os.path.join(human, "human1.jsonl"), "w").write(
            '{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\\nwhat is the current hunting state?\\n</user_query>"}]}}')
        sw = sweep_spawned_sessions(base, confirm=True)
        assert sw["found"] == 1 and not os.path.isdir(spawned), sw
        assert os.path.isdir(human), "operator-typed resume session must survive"
    finally:
        for e in ("HUNT_CHATS_DIR", "HUNT_PROJECTS_DIR", "HUNT_SESSION_STORES", "HUNT_ENGINE_CWDS"):
            os.environ.pop(e, None)
    print("sessions.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
