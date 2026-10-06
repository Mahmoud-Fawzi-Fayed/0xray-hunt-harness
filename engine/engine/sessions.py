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
    """Remove sessions no pool references: orphaned transcripts in MANAGED workspaces + empty chat
    dirs + empty workspace husks. Non-empty unmanaged/IDE chats are never touched."""
    inv = inventory(base)
    targets = list(inv["transcript_orphans"].values()) + inv["empty_chats"] + inv["husks"]
    out = {"orphans_found": len(targets), "removed": 0, "skipped_pooled": 0, "dry_run": not confirm,
           "by_kind": {"transcripts": len(inv["transcript_orphans"]),
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
        r = clear_orphans(base, confirm=True)
        assert r["removed"] >= 3, r                      # orphan1 + emptychat + emptyws husk
        assert is_alive("s1"), "pooled session must survive"
        assert os.path.isdir(os.path.join(projects, "root", "agent-transcripts", "ide-chat")), "unmanaged untouched"
        # drop_ids removes from BOTH stores but never a pooled id
        os.makedirs(os.path.join(tstore, "tmp1"))
        os.makedirs(os.path.join(chats, "wshash", "tmp1"))
        r = drop_ids(["tmp1", "s1"], base=base)
        assert r["removed"] == 2 and r["skipped_pooled"] == 1, r
        assert not session_dirs("tmp1") and is_alive("s1")
    finally:
        for e in ("HUNT_CHATS_DIR", "HUNT_PROJECTS_DIR", "HUNT_SESSION_STORES"):
            os.environ.pop(e, None)
    print("sessions.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
