#!/usr/bin/env python3
"""
authz.py — automated cross-account authorization (IDOR / BOLA) diff.

OWASP #1 (Broken Access Control) is the highest-yield, best-paying class and a scanner can't catch it
because authorization is business logic. With two stored identities A + B (see authn.py), replay the
SAME request as each and diff the responses. If B reads/writes A-owned data, that's a BOLA/IDOR
candidate for the agent/operator to confirm with a two-account PoC. This is a TRIAGE signal, never an
auto-submit, and it stays read-only.

CLI:
  python3 authz.py diff --slug <target> --url "https://host/api/orders/123" [--url ...]
  python3 authz.py diff --slug <target> --requests reqs.json      # [{"method","url","body"}, ...]
"""
import argparse
import difflib
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import netget  # noqa: E402

ID_SEG = re.compile(r"/\d{2,}(?:/|$)|[?&](?:id|user|account|order|uid|pid|oid|org|tenant)=", re.I)


def _similar(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def diff_one(method, url, body, slug, _get=None):
    g = _get or netget.get
    sa, ta, _ = g(url, method=method, data=body, ident="A", slug=slug)
    sb, tb, _ = g(url, method=method, data=body, ident="B", slug=slug)
    sim = round(_similar(ta or "", tb or ""), 3)
    has_id = bool(ID_SEG.search(url))
    # B reaching the same 2xx content as A on an id-bearing request => likely missing object-level authz
    flag = (200 <= (sb or 0) < 300) and (200 <= (sa or 0) < 300) and sim >= 0.9 and has_id
    return {"url": url, "method": method, "A_status": sa, "B_status": sb,
            "A_len": len(ta or ""), "B_len": len(tb or ""), "similarity": sim,
            "id_bearing": has_id, "bola_suspect": flag}


def diff(reqs, slug, _get=None):
    out = [diff_one(r.get("method", "GET"), r["url"], r.get("body"), slug, _get=_get)
           for r in reqs if r.get("url")]
    out.sort(key=lambda r: (not r["bola_suspect"], -r["similarity"]))
    return out


def _main(argv=None):
    ap = argparse.ArgumentParser(description="cross-account IDOR/BOLA diff")
    ap.add_argument("--base", default=os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    pd = sub.add_parser("diff"); pd.add_argument("--slug", required=True)
    pd.add_argument("--url", action="append", default=[]); pd.add_argument("--requests")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    os.environ.setdefault("HUNT_TARGET_SLUG", a.slug)
    reqs = json.load(open(a.requests)) if a.requests else []
    reqs += [{"method": "GET", "url": u} for u in a.url]
    if not reqs:
        print("provide --url or --requests", file=sys.stderr); return 2
    import authn
    if "B" not in authn.identities(a.slug, a.base):
        print(f"warn: no identity 'B' stored for {a.slug} — IDOR needs 2 accounts (authn.py set --ident B ...)",
              file=sys.stderr)
    res = diff(reqs, a.slug)
    print(json.dumps(res, indent=2))
    sus = [r for r in res if r["bola_suspect"]]
    print(f"\n{len(sus)}/{len(res)} BOLA-suspect — confirm each with a two-account PoC before drafting.",
          file=sys.stderr)
    return 0


def _selftest():
    def fake(url, method="GET", data=None, ident=None, slug=None, **k):
        if "orders/123" in url:                       # private object both accounts can read => BOLA
            return 200, "SECRET ORDER user A total=99.00 ..................................", {}
        if "profile" in url:                          # id-less page, legitimately per-account
            return (200, "A profile", {}) if ident == "A" else (200, "B profile", {})
        return 404, "", {}
    r = diff_one("GET", "https://x/api/orders/123", None, "t", _get=fake)
    assert r["bola_suspect"] is True, r
    r2 = diff_one("GET", "https://x/profile", None, "t", _get=fake)
    assert r2["bola_suspect"] is False, r2
    print("authz.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
