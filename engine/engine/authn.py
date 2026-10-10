#!/usr/bin/env python3
"""
authn.py — per-target authenticated HTTP sessions (operator-provided) for the hunt.

The paid bugs (IDOR/BOLA, business logic, GraphQL authz) live behind login. The operator drops a
real logged-in session per target; recon and the hunt agent then reach the authenticated surface,
and two identities (A + B) enable cross-account authorization (IDOR/BOLA) testing.

Storage (operational secret — NEVER committed to the repo): <base>/_auth/<slug>.json
  {
    "A": {"cookie": "k=v; k2=v2", "headers": {"X-Csrf":"..."}, "bearer": "eyJ..."},
    "B": {"cookie": "..."}                       # optional second account for cross-account tests
  }
Any of cookie / headers / bearer may be present. 'A' is primary (used for authenticated recon).

CLI:
  python3 authn.py set  --slug wyylde --ident A --cookie "sess=...; csrf=..." [--bearer eyJ... --header 'K: V']
  python3 authn.py show --slug wyylde
  python3 authn.py identities --slug wyylde
"""
import argparse
import json
import os
import re
import sys

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


def path_for(slug, base=DEFAULT_BASE):
    d = os.path.join(os.path.expanduser(base), "_auth")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, _slug(slug) + ".json")


def load(slug_or_path, base=DEFAULT_BASE):
    """Return {'A':{...}, 'B':{...}} or {} if none. Accepts a slug or an explicit file path."""
    p = slug_or_path if os.path.isfile(str(slug_or_path)) else path_for(slug_or_path, base)
    try:
        d = json.load(open(p))
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def identities(slug_or_path, base=DEFAULT_BASE):
    return sorted(k for k in load(slug_or_path, base) if isinstance(k, str))


def headers_for(ident="A", slug_or_path=None, sess=None, base=DEFAULT_BASE):
    """Request headers dict for identity A/B from the stored session (cookie + bearer + extra headers)."""
    data = sess if sess is not None else load(slug_or_path, base)
    s = (data or {}).get(ident or "A") or {}
    h = {str(k): str(v) for k, v in (s.get("headers") or {}).items()}
    if s.get("cookie"):
        h["Cookie"] = s["cookie"]
    if s.get("bearer"):
        h["Authorization"] = "Bearer " + str(s["bearer"]).replace("Bearer ", "").strip()
    return h


def configured(slug, base=DEFAULT_BASE):
    return bool(load(slug, base))


def status(slug, base=DEFAULT_BASE):
    d = load(slug, base)
    return {"configured": bool(d), "identities": sorted(d.keys()) if d else []}


def save(slug, ident, cookie=None, bearer=None, headers=None, base=DEFAULT_BASE, replace=False):
    p = path_for(slug, base)
    d = load(slug, base)
    entry = {} if replace else dict(d.get(ident, {}) or {})
    if cookie:
        entry["cookie"] = cookie
    elif replace:
        entry.pop("cookie", None)
    if bearer:
        entry["bearer"] = bearer
    elif replace:
        entry.pop("bearer", None)
    if headers:
        if replace:
            entry["headers"] = dict(headers)
        else:
            entry.setdefault("headers", {}).update(headers)
    elif replace:
        entry.pop("headers", None)
    d[ident] = entry
    json.dump(d, open(p, "w"), indent=2)
    os.chmod(p, 0o600)
    return p


def _main(argv=None):
    ap = argparse.ArgumentParser(description="per-target authenticated sessions")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("set"); ps.add_argument("--slug", required=True); ps.add_argument("--ident", default="A")
    ps.add_argument("--cookie"); ps.add_argument("--bearer"); ps.add_argument("--header", action="append", default=[])
    sh = sub.add_parser("show"); sh.add_argument("--slug", required=True)
    si = sub.add_parser("identities"); si.add_argument("--slug", required=True)
    st = sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "set":
        hdrs = {}
        for kv in a.header:
            if ":" in kv:
                k, v = kv.split(":", 1); hdrs[k.strip()] = v.strip()
        p = save(a.slug, a.ident, cookie=a.cookie, bearer=a.bearer, headers=hdrs or None, base=a.base)
        print(f"saved {a.ident} for {a.slug} -> {p}")
    elif a.cmd == "show":
        print(json.dumps(load(a.slug, a.base), indent=2))
    elif a.cmd == "identities":
        print(identities(a.slug, a.base) or "(none)")
    elif a.cmd == "selftest":
        import tempfile
        base = tempfile.mkdtemp()
        save("acme", "A", cookie="sid=aaa", bearer="tokA", base=base)
        save("acme", "B", cookie="sid=bbb", headers={"X-Org": "2"}, base=base)
        assert identities("acme", base) == ["A", "B"]
        ha = headers_for("A", "acme", base=base)
        assert ha["Cookie"] == "sid=aaa" and ha["Authorization"] == "Bearer tokA", ha
        hb = headers_for("B", "acme", base=base)
        assert hb["Cookie"] == "sid=bbb" and hb["X-Org"] == "2", hb
        assert configured("acme", base) and not configured("none", base)
        print("authn.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
