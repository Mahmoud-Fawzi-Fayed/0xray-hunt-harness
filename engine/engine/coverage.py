#!/usr/bin/env python3
"""
coverage.py — hunt coverage matrix + interesting-leads queue.

So "0 findings" is backed by VISIBLE coverage (what was tested, per class) instead of a black box,
and unproven-but-suspicious leads surface for the operator's expert finish (the 20%).

Reads <base>/<slug>/state.json {surface, tested, candidates, confirmed}.

CLI:
  python3 coverage.py show --slug <target> [--json]
  python3 coverage.py all
"""
import argparse
import json
import os
import sys

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def _load(slug, base):
    p = os.path.join(os.path.expanduser(base), slug, "state.json")
    try:
        return json.load(open(p))
    except Exception:  # noqa: BLE001
        return {}


def _tested_keys(tested):
    keys = set()
    for t in tested or []:
        if isinstance(t, dict):
            keys.add((t.get("url"), t.get("vuln_class")))
            keys.add(t.get("url"))
        elif isinstance(t, str):
            parts = t.split("|")
            if len(parts) == 4:                      # new: METHOD|url|param|class
                keys.add((parts[1], parts[3])); keys.add(parts[1])
            elif len(parts) == 3:                    # legacy: url|param|class
                keys.add((parts[0], parts[2])); keys.add(parts[0])
            elif "||" in t:                          # old: url||class
                u, c = t.split("||", 1)
                keys.add((u, c)); keys.add(u)
            else:
                keys.add(t)
        else:
            keys.add(t)
    return keys


def report(slug, base=DEFAULT_BASE):
    d = _load(slug, base)
    surface = d.get("surface") or []
    tk = _tested_keys(d.get("tested"))
    cand = d.get("candidates") or []
    conf = d.get("confirmed") or []
    by_class = {}
    for it in surface:
        c = it.get("vuln_class", "?")
        v = by_class.setdefault(c, {"total": 0, "tested": 0, "urls": set()})
        v["total"] += 1
        v["urls"].add(it.get("url"))
        if (it.get("url"), c) in tk or it.get("url") in tk:
            v["tested"] += 1
    matrix = {c: {"total": v["total"], "tested": v["tested"], "endpoints": len(v["urls"])}
              for c, v in sorted(by_class.items())}
    leads = [{"url": x.get("url"), "class": x.get("vuln_class"), "severity": x.get("severity"),
              "proof_note": x.get("proof_note", "")} for x in cand]
    security_tested = len(d.get("tested_checks") or {})
    return {"program": slug, "phase": d.get("phase"), "surface": len(surface),
            "tested": len(tk), "security_tested": security_tested,
            "candidates": len(cand), "confirmed": len(conf),
            "coverage_by_class": matrix, "leads": leads}


def fmt(r):
    L = [f"# Coverage — {r['program']} (phase={r.get('phase')})",
         f"surface={r['surface']}  tested={r['tested']}  security_tested={r.get('security_tested',0)}  candidates={r['candidates']}  confirmed={r['confirmed']}",
         "", "  class              tested/total   endpoints"]
    for c, v in r["coverage_by_class"].items():
        pct = round(100 * v["tested"] / v["total"]) if v["total"] else 0
        bar_w = 20
        filled = round(bar_w * pct / 100)
        bar = "█" * filled + "░" * (bar_w - filled)
        L.append(f"  {c:18s} {v['tested']}/{v['total']:<6} {bar} {pct:3d}%  {v['endpoints']}")
    if r["leads"]:
        L += ["", "INTERESTING LEADS (unproven — operator finish):"]
        for x in r["leads"][:30]:
            L.append(f"  [{x.get('severity') or '?'}] {x['class']} @ {x['url']}  {x.get('proof_note', '')}".rstrip())
    else:
        L += ["", "leads: none this pass"]
    return "\n".join(L)


def _main(argv=None):
    ap = argparse.ArgumentParser(description="hunt coverage + leads")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--json", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("show"); ps.add_argument("--slug", required=True)
    sub.add_parser("all")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    if a.cmd == "show":
        r = report(a.slug, a.base)
        print(json.dumps(r, indent=2) if a.json else fmt(r))
        return 0
    if a.cmd == "all":
        td = os.path.join(os.path.expanduser(a.base), "_targets")
        slugs = [f[:-5] for f in sorted(os.listdir(td))] if os.path.isdir(td) else []
        for s in slugs:
            if os.path.isdir(os.path.join(os.path.expanduser(a.base), s)):
                print(fmt(report(s, a.base)), "\n")
        return 0


def _selftest():
    import tempfile
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "acme"))
    st = {"name": "acme", "phase": "done",
          "surface": [{"url": "u1", "vuln_class": "idor"}, {"url": "u2", "vuln_class": "idor"},
                      {"url": "u1", "vuln_class": "xss"}],
          "tested": [{"url": "u1", "vuln_class": "idor"}],
          "candidates": [{"url": "u2", "vuln_class": "idor", "severity": "high", "proof_note": "B read A order"}],
          "confirmed": []}
    json.dump(st, open(os.path.join(base, "acme", "state.json"), "w"))
    r = report("acme", base)
    assert r["surface"] == 3 and r["candidates"] == 1, r
    assert r["coverage_by_class"]["idor"]["total"] == 2 and r["coverage_by_class"]["idor"]["tested"] == 1, r
    assert r["leads"][0]["url"] == "u2", r
    print("coverage.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
