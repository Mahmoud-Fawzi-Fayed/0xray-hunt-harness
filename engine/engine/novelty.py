#!/usr/bin/env python3
"""
novelty.py — surface change detection ("be first, avoid dups").

A duplicate is very often just someone who got there first. The cheapest structural way to
avoid dups is to hunt surface that just CHANGED — a new subdomain, a freshly deployed JS
bundle, a new API endpoint, a new parameter — before the crowd notices. Fresh surface is both
higher-signal (new code = new bugs) and lower-dup-risk (nobody has reported it yet).

This module snapshots a target's observed surface and diffs snapshots to emit the
"new since last time" delta. The ranker/operator treat that delta as top priority, and the
n8n monitor (separate hunting instance) calls `watch` on a schedule to fire alerts.

Design constraints: stdlib only, OFFLINE. It does NOT crawl — recon.py / osint.py (or n8n's
httpx/subfinder nodes) produce the observation; this module only stores + diffs it.

Snapshot schema (what a caller hands to snapshot()/watch()):
  {
    "subdomains": ["a.t.com", ...],
    "hosts":      [{"url": "https://a.t.com", "status": 200, "title": "...", "tech": [...]}, ...],
    "js":         [{"url": "https://a.t.com/app.js", "hash": "<sha256-or-etag>"}, ...],
    "endpoints":  ["https://a.t.com/api/v2/users", ...],
    "params":     ["https://a.t.com/search?q=", ...]
  }

Stored under <base>/_novelty/<target>/snapshot-<ts>.json with a `latest.json` pointer copy.

CLI:
  python3 engine/novelty.py snapshot --target t.com (--file obs.json | --stdin)
  python3 engine/novelty.py diff     --target t.com (--file new.json | --stdin) [--json]
  python3 engine/novelty.py watch    --target t.com (--file new.json | --stdin) [--json]
  python3 engine/novelty.py list     --target t.com
  python3 engine/novelty.py selftest
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# which snapshot keys we track, and how to reduce each to a comparable identity.
#   - set-keys compare by the raw string.
#   - js compares by url but reports a change when the hash moves (new deploy of the same file).
SET_KEYS = ("subdomains", "endpoints", "params")


def _now():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(target):
    return re.sub(r"[^a-z0-9._-]+", "-", (target or "unknown").strip().lower()).strip("-") or "unknown"


def _host_key(h):
    if not isinstance(h, dict):
        return str(h)
    return h.get("url") or h.get("host") or ""


def _js_map(snap):
    """url -> hash for the js list (tolerates malformed entries)."""
    out = {}
    for j in snap.get("js", []) or []:
        if not isinstance(j, dict):
            continue
        u = j.get("url")
        if u:
            out[str(u)] = str(j.get("hash", ""))
    return out


def _strset(seq):
    """Coerce an arbitrary iterable into a clean set of strings (drops None; never raises on mixed types)."""
    return {str(x) for x in (seq or []) if x is not None}


class Novelty:
    def __init__(self, target, base=DEFAULT_BASE):
        self.target = target
        self.dir = os.path.join(os.path.expanduser(base), "_novelty", _slug(target))
        os.makedirs(self.dir, exist_ok=True)
        self.latest_path = os.path.join(self.dir, "latest.json")

    def latest(self):
        if os.path.isfile(self.latest_path):
            try:
                return json.load(open(self.latest_path, encoding="utf-8"))
            except json.JSONDecodeError:
                return None
        return None

    def snapshot(self, obs):
        """Persist an observation as the new baseline. Returns the snapshot filename."""
        snap = {"target": self.target, "ts": _now()}
        for k in SET_KEYS:
            snap[k] = sorted(_strset(obs.get(k)))
        snap["hosts"] = sorted([h for h in (obs.get("hosts", []) or []) if isinstance(h, dict)], key=_host_key)
        snap["js"] = sorted([j for j in (obs.get("js", []) or []) if isinstance(j, dict)],
                            key=lambda j: j.get("url", "") or "")
        fname = os.path.join(self.dir, f"snapshot-{snap['ts']}.json")
        json.dump(snap, open(fname, "w", encoding="utf-8"), indent=2)
        json.dump(snap, open(self.latest_path, "w", encoding="utf-8"), indent=2)
        return fname

    def diff(self, obs, old=None):
        """Diff an observation against the stored latest (or a provided `old`). Pure — no write.

        Returns {"baseline": bool, "has_changes": bool, "new_*": [...], "removed_*": [...],
                 "changed_js": [{url, old, new}]}."""
        base = old if old is not None else self.latest()
        res = {"target": self.target, "baseline": base is None, "has_changes": False}
        if base is None:
            # no prior snapshot: EVERYTHING is new (first run) — flag as baseline, not "changes"
            for k in SET_KEYS:
                res["new_" + k] = sorted(_strset(obs.get(k)))
                res["removed_" + k] = []
            res["new_hosts"] = sorted([h for h in (obs.get("hosts", []) or []) if isinstance(h, dict)], key=_host_key)
            res["removed_hosts"] = []
            res["new_js"] = sorted(_js_map(obs).keys())
            res["removed_js"] = []
            res["changed_js"] = []
            return res

        for k in SET_KEYS:
            old_set = _strset(base.get(k))
            new_set = _strset(obs.get(k))
            res["new_" + k] = sorted(new_set - old_set)
            res["removed_" + k] = sorted(old_set - new_set)

        old_hosts = {_host_key(h): h for h in base.get("hosts", []) or []}
        new_hosts = {_host_key(h): h for h in obs.get("hosts", []) or []}
        res["new_hosts"] = [new_hosts[u] for u in sorted(set(new_hosts) - set(old_hosts)) if u]
        res["removed_hosts"] = [old_hosts[u] for u in sorted(set(old_hosts) - set(new_hosts)) if u]

        old_js, new_js = _js_map(base), _js_map(obs)
        res["new_js"] = sorted(set(new_js) - set(old_js))
        res["removed_js"] = sorted(set(old_js) - set(new_js))
        res["changed_js"] = [
            {"url": u, "old": old_js[u], "new": new_js[u]}
            for u in sorted(set(old_js) & set(new_js))
            if old_js[u] and new_js[u] and old_js[u] != new_js[u]
        ]

        res["has_changes"] = any(
            res[k] for k in res
            if (k.startswith("new_") or k.startswith("changed_")) and isinstance(res[k], list)
        )
        return res

    def watch(self, obs):
        """diff vs latest, THEN persist obs as the new baseline. Returns the diff.

        This is the n8n entry point: feed it the latest crawl, get back the delta to hunt,
        and the baseline is advanced so the next run only reports what is new after this one."""
        d = self.diff(obs)
        self.snapshot(obs)
        return d


def summarize(d):
    """One-line-per-category human summary of a diff dict."""
    if d.get("baseline"):
        n = sum(len(d.get("new_" + k, [])) for k in SET_KEYS) + len(d.get("new_hosts", []))
        return [f"baseline snapshot stored ({n} surface item(s)); no prior to diff against"]
    lines = []
    labels = [("new_subdomains", "new subdomain"), ("new_hosts", "new live host"),
              ("new_js", "new JS bundle"), ("changed_js", "CHANGED JS bundle (redeploy)"),
              ("new_endpoints", "new endpoint"), ("new_params", "new parameter")]
    for key, label in labels:
        items = d.get(key, [])
        if not items:
            continue
        lines.append(f"{len(items)} {label}(s):")
        for it in items[:12]:
            if isinstance(it, dict):
                lines.append("   + " + (it.get("url") or _host_key(it)))
            else:
                lines.append("   + " + str(it))
        if len(items) > 12:
            lines.append(f"   … +{len(items) - 12} more")
    return lines or ["no changes since last snapshot"]


# --------------------------------------------------------------------------- CLI
def _load_obs(args):
    if args.stdin:
        raw = sys.stdin.read()
    elif args.file:
        raw = open(os.path.expanduser(args.file), encoding="utf-8").read()
    else:
        print("error: provide --file obs.json or --stdin", file=sys.stderr)
        sys.exit(2)
    return json.loads(raw)


def _cmd_snapshot(args):
    f = Novelty(args.target, base=args.base).snapshot(_load_obs(args))
    print(f"snapshot: wrote {f}")
    return 0


def _cmd_diff(args):
    d = Novelty(args.target, base=args.base).diff(_load_obs(args))
    print(json.dumps(d, indent=2) if args.json else "\n".join(summarize(d)))
    return 0


def _cmd_watch(args):
    d = Novelty(args.target, base=args.base).watch(_load_obs(args))
    print(json.dumps(d, indent=2) if args.json else "\n".join(summarize(d)))
    return 0


def _cmd_list(args):
    nv = Novelty(args.target, base=args.base)
    snaps = sorted(f for f in os.listdir(nv.dir) if f.startswith("snapshot-"))
    for s in snaps:
        print("  " + s)
    print(f"list: {len(snaps)} snapshot(s) for {args.target}")
    return 0


def _cmd_selftest(_):
    import tempfile
    base = tempfile.mkdtemp()
    nv = Novelty("t.com", base=base)

    obs1 = {
        "subdomains": ["a.t.com", "b.t.com"],
        "hosts": [{"url": "https://a.t.com", "status": 200, "tech": ["next.js"]}],
        "js": [{"url": "https://a.t.com/app.js", "hash": "aaa"}],
        "endpoints": ["https://a.t.com/api/v1/users"],
        "params": ["https://a.t.com/search?q="],
    }
    d0 = nv.watch(obs1)
    assert d0["baseline"] is True, d0
    assert set(d0["new_subdomains"]) == {"a.t.com", "b.t.com"}, d0

    # second run: one new subdomain, one new endpoint, app.js redeployed (hash change)
    obs2 = {
        "subdomains": ["a.t.com", "b.t.com", "c.t.com"],
        "hosts": [{"url": "https://a.t.com", "status": 200, "tech": ["next.js"]},
                  {"url": "https://c.t.com", "status": 200, "tech": ["nginx"]}],
        "js": [{"url": "https://a.t.com/app.js", "hash": "bbb"},
               {"url": "https://c.t.com/main.js", "hash": "ccc"}],
        "endpoints": ["https://a.t.com/api/v1/users", "https://c.t.com/api/v2/admin"],
        "params": ["https://a.t.com/search?q="],
    }
    d = nv.diff(obs2)   # diff only — does not advance baseline
    assert d["baseline"] is False, d
    assert d["new_subdomains"] == ["c.t.com"], d
    assert d["new_endpoints"] == ["https://c.t.com/api/v2/admin"], d
    assert d["new_js"] == ["https://c.t.com/main.js"], d
    assert d["changed_js"] and d["changed_js"][0]["url"] == "https://a.t.com/app.js", d
    assert d["changed_js"][0]["old"] == "aaa" and d["changed_js"][0]["new"] == "bbb", d
    assert any(_host_key(h) == "https://c.t.com" for h in d["new_hosts"]), d
    assert d["has_changes"] is True, d

    # watch advances the baseline: re-running the SAME obs now shows no changes
    nv.watch(obs2)
    d2 = nv.diff(obs2)
    assert d2["has_changes"] is False, d2
    print("novelty.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="surface change detection")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, extra in [
        ("snapshot", _cmd_snapshot, True), ("diff", _cmd_diff, True),
        ("watch", _cmd_watch, True), ("list", _cmd_list, False), ("selftest", _cmd_selftest, False),
    ]:
        p = sub.add_parser(name)
        if name != "selftest":
            p.add_argument("--target", required=True)
        if extra:
            p.add_argument("--file")
            p.add_argument("--stdin", action="store_true")
        if name in ("diff", "watch"):
            p.add_argument("--json", action="store_true")
        p.set_defaults(fn=fn)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
