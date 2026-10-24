#!/usr/bin/env python3
"""
coverage.py — hunt coverage matrix + interesting-leads queue.

So "0 findings" is backed by VISIBLE coverage (what was tested, per class) instead of a black box,
and unproven-but-suspicious leads surface for the operator's expert finish (the 20%).

Coverage is keyed by (method, url, vuln_class, role) — not just URL. A GET and POST to the same
URL are separate operations; testing IDOR doesn't count as testing XSS; testing as user_a doesn't
count as testing as user_b.

Reads <base>/<slug>/state.json {surface, tested, tested_checks, candidates, confirmed, test_plan}.

CLI:
  python3 coverage.py show --slug <target> [--json]
  python3 coverage.py all
  python3 coverage.py selftest
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


def _parse_tested(tested):
    """Parse tested entries into structured records: {(method, url, vuln_class): timestamp}.
    Handles 4-field (METHOD|url|param|class), 3-field legacy, dict, and old url||class formats."""
    records = {}
    if isinstance(tested, dict):
        for k, ts in tested.items():
            parts = k.split("|")
            if len(parts) == 4:
                records[(parts[0], parts[1], parts[3])] = ts
            elif len(parts) == 3:
                records[("*", parts[0], parts[2])] = ts
            else:
                records[("*", k, "")] = ts
        return records
    for t in tested or []:
        if isinstance(t, dict):
            m = t.get("method", "GET")
            u = t.get("url", "")
            c = t.get("vuln_class", "")
            records[(m, u, c)] = 0.0
        elif isinstance(t, str):
            parts = t.split("|")
            if len(parts) == 4:
                records[(parts[0], parts[1], parts[3])] = 0.0
            elif len(parts) == 3:
                records[("*", parts[0], parts[2])] = 0.0
            elif "||" in t:
                u, c = t.split("||", 1)
                records[("*", u, c)] = 0.0
            else:
                records[("*", t, "")] = 0.0
    return records


def _is_tested(method, url, vuln_class, tested_records):
    """Check if a specific (method, url, class) combination is tested.
    A wildcard method '*' matches any method (legacy compat)."""
    if (method, url, vuln_class) in tested_records:
        return True
    if ("*", url, vuln_class) in tested_records:
        return True
    return False


def _testplan_coverage(test_plan):
    """Extract coverage from test_plan cases. Returns {(method, url, category): status}."""
    covered = {}
    if not test_plan:
        return covered
    cases = test_plan if isinstance(test_plan, list) else (
        test_plan.get("cases") or test_plan.get("test_cases") or [])
    for case in cases:
        if not isinstance(case, dict):
            continue
        m = case.get("method", "GET")
        u = case.get("endpoint") or case.get("url", "")
        c = case.get("category") or case.get("vuln_class", "")
        covered[(m, u, c)] = case.get("status", "pending")
    return covered


def report(slug, base=DEFAULT_BASE):
    d = _load(slug, base)
    surface = d.get("surface") or []
    tested_records = _parse_tested(d.get("tested"))
    tested_checks = d.get("tested_checks") or {}
    cand = d.get("candidates") or []
    conf = d.get("confirmed") or []
    plan_cov = _testplan_coverage(d.get("test_plan"))

    by_class = {}
    by_operation = {}
    roles_seen = set()

    for it in surface:
        m = it.get("method", "GET")
        u = it.get("url", "")
        c = it.get("vuln_class", "?")
        role = it.get("role", "default")
        roles_seen.add(role)

        v = by_class.setdefault(c, {"total": 0, "tested": 0, "endpoints": set()})
        v["total"] += 1
        v["endpoints"].add(u)
        is_covered = (_is_tested(m, u, c, tested_records) or
                      plan_cov.get((m, u, c)) in ("tested", "confirmed", "disproved"))
        if is_covered:
            v["tested"] += 1

        op_key = (m, u)
        op = by_operation.setdefault(op_key, {"classes": {}, "roles": set()})
        op["roles"].add(role)
        op["classes"][c] = "tested" if is_covered else "pending"

    matrix = {c: {"total": v["total"], "tested": v["tested"],
                   "endpoints": len(v["endpoints"])}
              for c, v in sorted(by_class.items())}

    role_coverage = {}
    for role in sorted(roles_seen):
        role_ops = [(m, u) for (m, u), op in by_operation.items() if role in op["roles"]]
        role_tested = sum(1 for m, u in role_ops
                         if any(v == "tested" for v in by_operation[(m, u)]["classes"].values()))
        role_coverage[role] = {"operations": len(role_ops), "tested": role_tested}

    operations = []
    for (m, u), op in sorted(by_operation.items()):
        classes_detail = {}
        for c, status in op["classes"].items():
            checks = tested_checks.get(f"{m}|{u}||{c}", [])
            classes_detail[c] = {"status": status, "checks": checks,
                                 "roles_tested": sorted(op["roles"])}
        operations.append({"method": m, "url": u, "classes": classes_detail})

    leads = [{"url": x.get("url"), "class": x.get("vuln_class"),
              "severity": x.get("severity"), "proof_note": x.get("proof_note", "")}
             for x in cand]

    unique_tested = sum(v["tested"] for v in by_class.values())

    return {"program": slug, "phase": d.get("phase"),
            "surface": len(surface), "tested": unique_tested,
            "security_tested": len(tested_checks),
            "candidates": len(cand), "confirmed": len(conf),
            "coverage_by_class": matrix,
            "coverage_by_role": role_coverage,
            "operations": operations[:50],
            "leads": leads}


def fmt(r):
    L = [f"# Coverage — {r['program']} (phase={r.get('phase')})",
         f"surface={r['surface']}  tested={r['tested']}  security_tested={r.get('security_tested',0)}"
         f"  candidates={r['candidates']}  confirmed={r['confirmed']}",
         "", "  ## Per vuln class",
         "  class              tested/total   endpoints"]
    for c, v in r["coverage_by_class"].items():
        pct = round(100 * v["tested"] / v["total"]) if v["total"] else 0
        bar_w = 20
        filled = round(bar_w * pct / 100)
        bar = "█" * filled + "░" * (bar_w - filled)
        L.append(f"  {c:18s} {v['tested']}/{v['total']:<6} {bar} {pct:3d}%  {v['endpoints']}")

    if r.get("coverage_by_role"):
        L += ["", "  ## Per role"]
        for role, rv in r["coverage_by_role"].items():
            pct = round(100 * rv["tested"] / rv["operations"]) if rv["operations"] else 0
            L.append(f"  {role:18s} {rv['tested']}/{rv['operations']} operations tested ({pct}%)")

    ops = r.get("operations", [])
    if ops:
        L += ["", "  ## Per operation (top 20)"]
        for op in ops[:20]:
            parts = []
            for cls, detail in op["classes"].items():
                status = detail["status"]
                checks = detail.get("checks", [])
                check_str = f" [{','.join(checks)}]" if checks else ""
                roles = detail.get("roles_tested", [])
                role_str = f" ({','.join(roles)})" if roles and roles != ["default"] else ""
                parts.append(f"{cls}:{status}{check_str}{role_str}")
            L.append(f"  {op['method']:6s} {op['url'][:60]:60s} {' | '.join(parts)}")

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
        print(json.dumps(r, indent=2, default=list) if a.json else fmt(r))
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
          "surface": [
              {"url": "u1", "method": "GET", "vuln_class": "idor"},
              {"url": "u1", "method": "POST", "vuln_class": "idor"},
              {"url": "u2", "method": "GET", "vuln_class": "idor"},
              {"url": "u1", "method": "GET", "vuln_class": "xss"},
              {"url": "u3", "method": "GET", "vuln_class": "bac", "role": "user_a"},
              {"url": "u3", "method": "GET", "vuln_class": "bac", "role": "user_b"},
          ],
          "tested": {"GET|u1||idor": 1.0, "POST|u1||idor": 1.0},
          "tested_checks": {"GET|u1||idor": ["horizontal_idor"]},
          "candidates": [{"url": "u2", "vuln_class": "idor", "severity": "high",
                          "proof_note": "B read A order"}],
          "confirmed": [],
          "test_plan": {"cases": [
              {"method": "GET", "endpoint": "u3", "category": "bac", "status": "tested"},
          ]}}
    json.dump(st, open(os.path.join(base, "acme", "state.json"), "w"))
    r = report("acme", base)

    assert r["surface"] == 6, r["surface"]
    assert r["candidates"] == 1, r["candidates"]
    # idor: 3 surface, 2 tested (GET u1 + POST u1), u2 not tested
    assert r["coverage_by_class"]["idor"]["total"] == 3, r["coverage_by_class"]["idor"]
    assert r["coverage_by_class"]["idor"]["tested"] == 2, r["coverage_by_class"]["idor"]
    # xss: 1 total, 0 tested — testing GET u1 for idor does NOT count as xss
    assert r["coverage_by_class"]["xss"]["total"] == 1, r["coverage_by_class"]["xss"]
    assert r["coverage_by_class"]["xss"]["tested"] == 0, r["coverage_by_class"]["xss"]
    # bac: 2 total, 2 tested via test_plan
    assert r["coverage_by_class"]["bac"]["total"] == 2, r["coverage_by_class"]["bac"]
    assert r["coverage_by_class"]["bac"]["tested"] == 2, r["coverage_by_class"]["bac"]
    # Per-role
    assert "user_a" in r["coverage_by_role"], r["coverage_by_role"]
    assert "user_b" in r["coverage_by_role"], r["coverage_by_role"]
    # Leads
    assert r["leads"][0]["url"] == "u2", r["leads"]
    # Format
    text = fmt(r)
    assert "Per vuln class" in text and "Per role" in text

    print("coverage.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
