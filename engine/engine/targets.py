#!/usr/bin/env python3
"""
targets.py — one registry for every program you hunt + monitor.

One engine scope.json per program under <base>/_targets/<program>.json. The novelty monitor (via the
bridge /targets endpoint) and the orchestrator both read from here, so adding, changing, or removing a
target — or handing over a full scope — updates everything in one place. No more editing the n8n node.

Add accepts ANY scope shape (H1/Bugcrowd/YWH export, {in_scope:[...]}, or a bare host list) — it's
normalized through scopefetch into the engine scope {name,in_scope,out_of_scope,seeds} plus the set of
apexes to monitor.

CLI:
  python3 engine/targets.py add    --program paddle --scope-file paddle.json   # any scope shape
  echo "$SCOPE_JSON" | python3 engine/targets.py add --program paddle --stdin
  python3 engine/targets.py list
  python3 engine/targets.py monitor [--json]        # flat [{target,program}] the monitor diffs
  python3 engine/targets.py show    --program paddle
  python3 engine/targets.py remove  --program paddle
  python3 engine/targets.py selftest
"""
import argparse
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import scopefetch as SF   # noqa: E402

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def _dir(base):
    d = os.path.join(os.path.expanduser(base), "_targets")
    os.makedirs(d, exist_ok=True)
    return d


def _slug(p):
    return re.sub(r"[^a-z0-9._-]+", "-", str(p or "").strip().lower()).strip("-") or "unknown"


# two-label public suffixes where the registrable apex needs THREE labels (x.vwfs.co.za -> vwfs.co.za)
_TWO_LABEL_TLDS = {
    "com.cn", "net.cn", "org.cn", "co.uk", "org.uk", "gov.uk", "ac.uk", "co.za", "com.au", "net.au",
    "org.au", "com.br", "com.ar", "com.mx", "co.in", "co.kr", "com.tw", "com.tr", "co.jp", "com.sg",
    "com.hk", "com.my", "co.nz", "com.co", "com.pe", "com.ph", "com.vn", "co.id", "com.ua", "co.il",
}


def _apex(h):
    h = (h or "").lstrip("*").lstrip(".").lower().split("/")[0]
    parts = [x for x in h.split(".") if x]
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LABEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def add(program, scope_blob, base=DEFAULT_BASE):
    """Normalize any scope blob -> engine scope + monitor apexes, persist it. Returns (path, scope)."""
    scope = SF.convert(scope_blob, program)                 # handles items[]/in_scope/list shapes
    scope = {k: v for k, v in scope.items() if not k.startswith("_")}
    apex = sorted({_apex(h) for h in scope.get("in_scope", []) if _apex(h)})
    if not apex and scope.get("seeds"):
        apex = sorted({_apex(s) for s in scope["seeds"]})
    scope["monitor_apexes"] = apex
    path = os.path.join(_dir(base), _slug(program) + ".json")
    json.dump(scope, open(path, "w"), indent=2)
    return path, scope


def load(program, base=DEFAULT_BASE):
    path = os.path.join(_dir(base), _slug(program) + ".json")
    return json.load(open(path)) if os.path.isfile(path) else None


def remove(program, base=DEFAULT_BASE):
    path = os.path.join(_dir(base), _slug(program) + ".json")
    if os.path.isfile(path):
        os.remove(path)
        return True
    return False


def all_targets(base=DEFAULT_BASE):
    d = _dir(base)
    out = []
    for f in sorted(os.listdir(d)):
        if f.endswith(".json"):
            try:
                out.append(json.load(open(os.path.join(d, f))))
            except (json.JSONDecodeError, OSError):
                continue
    return out


def monitor_list(base=DEFAULT_BASE):
    """Flat [{target, program}] of apexes to diff across every registered program (deduped)."""
    out, seen = [], set()
    for sc in all_targets(base):
        prog = sc.get("name", "?")
        for a in sc.get("monitor_apexes") or []:
            if a and a not in seen:
                seen.add(a)
                out.append({"target": a, "program": prog})
    return out


# --------------------------------------------------------------------------- CLI
def _blob(args):
    if getattr(args, "stdin", False):
        return json.loads(sys.stdin.read() or "{}")
    if getattr(args, "scope_file", None):
        return json.load(open(os.path.expanduser(args.scope_file)))
    print("add: provide --scope-file f.json or --stdin", file=sys.stderr)
    sys.exit(2)


def _cmd_add(a):
    path, sc = add(a.program, _blob(a), base=a.base)
    print(f"added {a.program}: {len(sc['in_scope'])} in-scope, monitor {len(sc['monitor_apexes'])} apex(es) "
          f"{sc['monitor_apexes']} -> {path}")
    return 0


def _cmd_list(a):
    t = all_targets(a.base)
    for sc in t:
        print(f"  {sc.get('name'):24.24s} in-scope={len(sc.get('in_scope', []))} "
              f"monitor={','.join(sc.get('monitor_apexes', []))}")
    print(f"targets: {len(t)} program(s)")
    return 0


def _cmd_monitor(a):
    ml = monitor_list(a.base)
    print(json.dumps({"targets": ml}, indent=2) if a.json else
          "\n".join(f"  {m['target']}  ({m['program']})" for m in ml) or "  (none)")
    return 0


def _cmd_show(a):
    sc = load(a.program, a.base)
    print(json.dumps(sc, indent=2) if sc else f"no such target: {a.program}")
    return 0 if sc else 1


def _cmd_remove(a):
    print("removed" if remove(a.program, a.base) else "not found")
    return 0


def _cmd_selftest(_a):
    import tempfile
    base = tempfile.mkdtemp()
    ywh = {"items": [{"scope": "*.paddle.com", "scope_type": "web-application"},
                     {"scope": "https://api.paddle.com", "scope_type": "api"},
                     {"scope": "Paddle mobile app", "scope_type": "other"}]}
    _, sc = add("paddle", ywh, base=base)
    assert "paddle.com" in sc["monitor_apexes"], sc
    assert "*.paddle.com" in sc["in_scope"], sc
    add("acme", ["a.acme.com", "b.acme.io"], base=base)
    ml = monitor_list(base)
    apexes = {m["target"] for m in ml}
    assert {"paddle.com", "acme.com", "acme.io"} <= apexes, ml
    assert all("program" in m for m in ml)
    assert remove("acme", base=base) and not remove("acme", base=base)
    assert {m["target"] for m in monitor_list(base)} == {"paddle.com"}
    print("targets.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="program/target registry")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("add"); pa.add_argument("--program", required=True)
    pa.add_argument("--scope-file"); pa.add_argument("--stdin", action="store_true"); pa.set_defaults(fn=_cmd_add)
    sub.add_parser("list").set_defaults(fn=_cmd_list)
    pm = sub.add_parser("monitor"); pm.add_argument("--json", action="store_true"); pm.set_defaults(fn=_cmd_monitor)
    ps = sub.add_parser("show"); ps.add_argument("--program", required=True); ps.set_defaults(fn=_cmd_show)
    pr = sub.add_parser("remove"); pr.add_argument("--program", required=True); pr.set_defaults(fn=_cmd_remove)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
