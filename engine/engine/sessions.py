#!/usr/bin/env python3
"""
sessions.py — GUARDED session management. Nothing is ever deleted automatically; removal requires an
explicit --confirm. This is the only sanctioned way to clear sessions (the "restrict removal to one
solution" control).

Two kinds of session state:
  - chat dirs on disk: ~/.cursor/chats/<workspace>/<id>   (accumulate; orphaned ones are safe to clear)
  - per-target hunt session pools: <base>/_sessions/<slug>/state.json  (active hunts resume these)

Safety rules (enforced in code):
  * DRY-RUN by default — prints what WOULD be removed; deletes only with --confirm.
  * NEVER removes a session id that is in a RUNNING target's pool (live hunts keep working).
  * --all clears only ORPHANED chat dirs (not referenced by any pool); pooled ids are skipped.
  * --reset <slug> clears that target's pool + its chats (only when the target is not running).

CLI:
  python3 sessions.py list                       # inventory: chats on disk, pools, orphans
  python3 sessions.py clear --all                # DRY-RUN: show orphaned chats that would be removed
  python3 sessions.py clear --all --confirm      # actually remove orphaned chats
  python3 sessions.py reset --slug wyylde --confirm   # reset one target's session pool + chats
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
CHATS = os.path.expanduser("~/.cursor/chats")


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


def _pools(base):
    """{slug: [session ids]} from <base>/_sessions/*/state.json."""
    out = {}
    for f in glob.glob(os.path.join(os.path.expanduser(base), "_sessions", "*", "state.json")):
        slug = os.path.basename(os.path.dirname(f))
        try:
            out[slug] = [str(x) for x in json.load(open(f)).get("ids", [])]
        except Exception:  # noqa: BLE001
            out[slug] = []
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


def _chat_dirs():
    return [d for d in glob.glob(os.path.join(CHATS, "*", "*")) if os.path.isdir(d)]


def inventory(base=DEFAULT_BASE):
    pools = _pools(base)
    running = _running_slugs()
    pooled_ids = {i for ids in pools.values() for i in ids}
    chats = _chat_dirs()
    orphans = [d for d in chats if os.path.basename(d) not in pooled_ids]
    return {"pools": pools, "running": sorted(running), "pooled_ids": pooled_ids,
            "chats": chats, "orphans": orphans}


def clear_orphans(base=DEFAULT_BASE, confirm=False):
    inv = inventory(base)
    out = {"orphans_found": len(inv["orphans"]), "removed": 0, "skipped_pooled": 0, "dry_run": not confirm}
    for d in inv["orphans"]:
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
    """Remove SPECIFIC chat dirs by session id — used to clean up ephemeral one-shot sessions (e.g.
    verify triager runs) right after they finish. Safety: an id that is in ANY target's pool is
    never removed, so a live hunt can never lose a session to this."""
    pooled = {i for ids_ in _pools(base).values() for i in ids_}
    removed, skipped = 0, 0
    for sid in (ids or []):
        sid = re.sub(r"[^A-Za-z0-9._-]", "", str(sid or ""))
        if not sid:
            continue
        if sid in pooled:
            skipped += 1
            continue
        for cdir in glob.glob(os.path.join(CHATS, "*", sid)):
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
    ids = inv["pools"].get(slug, [])
    out = {"slug": slug, "pool_ids": ids, "chats_removed": 0, "pool_cleared": False, "dry_run": not confirm}
    if not confirm:
        return out
    for sid in ids:
        for cdir in glob.glob(os.path.join(CHATS, "*", sid)):
            try:
                shutil.rmtree(cdir)
                out["chats_removed"] += 1
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
    pc = sub.add_parser("clear"); pc.add_argument("--all", action="store_true"); pc.add_argument("--confirm", action="store_true")
    pr = sub.add_parser("reset"); pr.add_argument("--slug", required=True); pr.add_argument("--confirm", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    if a.cmd == "list":
        inv = inventory(a.base)
        print(f"chat dirs on disk : {len(inv['chats'])}")
        print(f"orphaned (safe)   : {len(inv['orphans'])}")
        print(f"pooled (in pools) : {len(inv['pooled_ids'])}")
        print(f"running hunts     : {', '.join(inv['running']) or '(none)'}")
        for s, ids in inv["pools"].items():
            print(f"  pool {s}: {len(ids)} session(s){' [RUNNING — protected]' if s in inv['running'] else ''}")
        return 0
    if a.cmd == "clear":
        r = clear_orphans(a.base, confirm=a.confirm)
        tag = "REMOVED" if a.confirm else "DRY-RUN (would remove)"
        print(f"{tag} {r['removed'] if a.confirm else r['orphans_found']} orphaned chat(s); "
              f"skipped {r['skipped_pooled']} pooled. " + ("" if a.confirm else "Re-run with --confirm to delete."))
        return 0
    if a.cmd == "reset":
        r = reset_target(a.slug, a.base, confirm=a.confirm)
        if r.get("error"):
            print("ERROR:", r["error"], file=sys.stderr); return 1
        print(("DRY-RUN would reset" if not a.confirm else "reset") + f" {r['slug']}: "
              f"{len(r['pool_ids'])} pool session(s), {r['chats_removed']} chat(s) removed. "
              + ("" if a.confirm else "Re-run with --confirm."))
        return 0


def _selftest():
    import tempfile
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "_sessions", "acme"))
    json.dump({"ids": ["s1", "s2"]}, open(os.path.join(base, "_sessions", "acme", "state.json"), "w"))
    pools = _pools(base)
    assert pools["acme"] == ["s1", "s2"], pools
    # dry-run never deletes
    r = clear_orphans(base, confirm=False)
    assert r["dry_run"] is True and r["removed"] == 0, r
    print("sessions.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
