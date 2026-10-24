#!/usr/bin/env python3
"""
scopefetch.py — turn a platform scope blob (H1 / Bugcrowd / YesWeHack, public OR private) into the
engine scope.json the orchestrator consumes: {name, in_scope[], out_of_scope[], seeds[]}.

The agent fetches scope via the bb-platforms MCP, then pipes it here:
  - find program : search_programs(query, platform)
  - YWH (private): login_yeswehack (TOTP) -> get_yeswehack_program(slug)  [has exact scope strings]
  - any platform : get_scope(platform, program)  -> in/out scope assets
Private programs work the same once you're authenticated to that platform.

Accepts, flexibly:
  - {"items":[{"scope":"*.x.com","scope_type":"web-application"}, ...]}        (YWH export shape)
  - {"in_scope":[...], "out_of_scope":[...] | "out_of_scope_explicit":[...]}   (already close)
  - {"in_scope":[{"asset":"x"}|{"scope":"x"}|{"target":"x"}], ...}             (get_scope style)
  - a bare JSON list of strings
Only host-like web/api/url assets become in_scope (mobile/source/"Other" free-text are dropped).

CLI:
  python3 engine/scopefetch.py convert --name acme --file scope.json [--out scope.json] [--seed-limit 5]
  python3 engine/scopefetch.py selftest
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse

HOST_RE = re.compile(r"^\*?\.?[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$")
WEB_TYPES = {"web-application", "web", "api", "url", "website", "wildcard", "domain", "ip-address", ""}


def _host_and_path(s):
    """Normalize scope entry to (host/wildcard, path_prefix_or_None)."""
    if not isinstance(s, str):
        return None, None
    s = s.strip()
    if not s or " " in s:
        return None, None
    path = None
    if "://" in s:
        parsed = urlparse(s)
        p = (parsed.path or "").rstrip("*").rstrip("/")
        if p and p != "/":
            path = p
        s = parsed.netloc or s
    s = s.split("/")[0].strip().lower().rstrip(".")
    if s.startswith("*."):
        core = s[2:]
    elif s.startswith("."):
        core = s[1:]
    else:
        core = s
    return (s if HOST_RE.match(core) else None), path


def _host(s):
    """Normalize one scope entry to a host/wildcard, or None if it isn't host-like."""
    h, _ = _host_and_path(s)
    return h


def _entries(blob, key):
    out = []
    v = blob.get(key) if isinstance(blob, dict) else None
    for x in (v or []):
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            out.append(x.get("scope") or x.get("asset") or x.get("target") or x.get("identifier") or "")
    return out


def _type_ok(it):
    if not isinstance(it, dict):
        return True
    t = (it.get("scope_type") or it.get("asset_type") or it.get("type") or "").lower()
    return (t in WEB_TYPES) or ("web" in t) or ("api" in t) or ("url" in t) or ("domain" in t)


def convert(blob, name, seed_limit=50):     # seed ALL concrete in-scope hosts (not just a handful) so
                                            # recon+hunt covers sandbox/vendors/etc, not only the primary host
    in_hosts, out_hosts, dropped = set(), set(), []
    path_restrictions = {}

    def add_in(s):
        h, path = _host_and_path(s)
        if h:
            in_hosts.add(h)
            if path:
                path_restrictions.setdefault(h, [])
                if path not in path_restrictions[h]:
                    path_restrictions[h].append(path)
        else:
            dropped.append(s)

    if isinstance(blob, list):
        for s in blob:
            add_in(s)
    elif isinstance(blob, dict) and "items" in blob:                 # YWH export
        for it in blob["items"]:
            s = it.get("scope") if isinstance(it, dict) else it
            (add_in(s) if _type_ok(it) else dropped.append(s))
    else:                                                            # explicit in/out
        for s in _entries(blob, "in_scope") or _entries(blob, "inScope") or _entries(blob, "targets"):
            add_in(s)
        for key in ("out_of_scope", "out_of_scope_explicit", "outOfScope"):
            for s in _entries(blob, key):
                h = _host(s)
                if h:
                    out_hosts.add(h)

    seeds, seen = [], set()
    for h in sorted(in_hosts):
        apex = h[2:] if h.startswith("*.") else h
        if apex not in seen and "*" not in apex:
            seen.add(apex)
            seeds.append("https://" + apex)
        if len(seeds) >= seed_limit:
            break

    result = {"name": name, "in_scope": sorted(in_hosts), "out_of_scope": sorted(out_hosts),
              "seeds": seeds, "_dropped_non_host": [d for d in dropped if d][:20]}
    if path_restrictions:
        result["path_restrictions"] = path_restrictions
    return result


def _cmd_convert(a):
    blob = json.load(open(os.path.expanduser(a.file)))
    sc = convert(blob, a.name, seed_limit=a.seed_limit)
    out = a.out or f"{a.name}-scope.json"
    json.dump({k: v for k, v in sc.items() if not k.startswith("_")}, open(out, "w"), indent=2)
    print(f"scopefetch: {len(sc['in_scope'])} in-scope, {len(sc['out_of_scope'])} out, "
          f"{len(sc['seeds'])} seed(s) -> {out}")
    if sc["_dropped_non_host"]:
        print("  (dropped non-host entries: " + ", ".join(sc["_dropped_non_host"][:6]) + " ...)")
    return 0


def _selftest(_a=None):
    ywh = {"items": [
        {"scope": "*.acme.com", "scope_type": "web-application"},
        {"scope": "https://api.acme.com", "scope_type": "api"},
        {"scope": "ExpressVPN APIs", "scope_type": "api"},                 # free text -> drop
        {"scope": "ExpressVPN VPN servers", "scope_type": "other"},        # non-host -> drop
        {"scope": "app.expressmailguard.com", "scope_type": "web-application"},
    ]}
    sc = convert(ywh, "acme")
    assert "*.acme.com" in sc["in_scope"] and "api.acme.com" in sc["in_scope"], sc
    assert "app.expressmailguard.com" in sc["in_scope"], sc
    assert "https://api.acme.com" in sc["seeds"] or "https://acme.com" in sc["seeds"], sc
    assert all("ExpressVPN" not in x for x in sc["in_scope"]), sc

    paddle = {"in_scope": ["api.paddle.com", "www.paddle.com"],
              "out_of_scope_explicit": ["buy.paddle.com"]}
    sc2 = convert(paddle, "paddle")
    assert "api.paddle.com" in sc2["in_scope"] and "buy.paddle.com" in sc2["out_of_scope"], sc2
    assert "https://api.paddle.com" in sc2["seeds"], sc2

    sc3 = convert(["a.com", "https://b.com/x", "not a host"], "list")
    assert sc3["in_scope"] == ["a.com", "b.com"], sc3
    print("scopefetch.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="platform scope -> engine scope.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("convert")
    pc.add_argument("--name", required=True)
    pc.add_argument("--file", required=True)
    pc.add_argument("--out", default=None)
    pc.add_argument("--seed-limit", type=int, default=50)
    pc.set_defaults(fn=_cmd_convert)
    sub.add_parser("selftest").set_defaults(fn=_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
