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


_ID_KEY = re.compile(r"(?:^|_)(id|uuid|guid|key|ref|slug|number|no)$", re.I)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _extract_ids(text, limit=12):
    """Harvest plausible object identifiers from a body A can read: values of id-ish JSON keys, bare
    UUIDs, and long numeric ids. These become the <id> we then try to read AS B (the IDOR test)."""
    ids = []
    try:
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if isinstance(v, (str, int)) and _ID_KEY.search(str(k)) and 2 <= len(str(v)) <= 64:
                        ids.append(str(v))
                    else:
                        walk(v)
            elif isinstance(o, list):
                for x in o[:25]:
                    walk(x)
        walk(json.loads(text))
    except Exception:  # noqa: BLE001
        pass
    ids += _UUID.findall(text or "")
    seen, out = set(), []
    for i in ids:
        if i not in seen and 2 <= len(i) <= 64 and not i.lower() in ("true", "false", "null"):
            seen.add(i)
            out.append(i)
    return out[:limit]


def _object_urls(base_url, ids):
    """From a list/collection url + A's object ids, build object-by-id URLs to probe as B: both
    `<url>/<id>` (collection -> object) and `<parent>/<id>` (a list endpoint -> its sibling object,
    e.g. /folders/selector-list + id -> /folders/<id>). Bounded; wrong guesses just 404 (no false +)."""
    u = base_url.split("?", 1)[0].rstrip("/")
    parent = u.rsplit("/", 1)[0] if u.count("/") > 2 else u
    out = []
    for i in ids:
        out.append(f"{u}/{i}")
        if parent and parent != u:
            out.append(f"{parent}/{i}")
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res[:20]


def id_oracle(base_url, slug, _get=None):
    """IDOR ID-ORACLE — the primitive a plain A-vs-B diff misses on list/self endpoints. As A, read
    base_url, harvest A's object ids, then try to read A's objects AS B. A bola_suspect means B read
    A-owned data => IDOR/BOLA candidate. Read-only, bounded. Returns suspect diffs (may be empty)."""
    g = _get or netget.get
    try:
        sa, ta, _ = g(base_url, method="GET", ident="A", slug=slug)
    except Exception:  # noqa: BLE001
        return []
    if not (200 <= (sa or 0) < 300) or not ta:
        return []
    suspects = []
    for ou in _object_urls(base_url, _extract_ids(ta)):
        try:
            d = diff_one("GET", ou, None, slug, _get=g)
        except Exception:  # noqa: BLE001
            continue
        if d.get("bola_suspect"):
            suspects.append(d)
    return suspects


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
