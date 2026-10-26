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

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def _load(slug, base):
    p = os.path.join(os.path.expanduser(base), slug, "state.json")
    try:
        return json.load(open(p))
    except Exception:  # noqa: BLE001
        return {}


def _parse_tested(tested):
    """Parse tested entries into a dict keyed by case_id hash AND legacy tuples.
    Returns {hash_or_tuple: timestamp}. Hash keys (16-char hex) are stored as-is.
    Legacy pipe-delimited keys are converted to both their hash and tuple form."""
    records = {}
    if isinstance(tested, dict):
        for k, ts in tested.items():
            ks = str(k)
            # Hash-based key (16 hex chars) — store as-is
            if len(ks) == 16 and all(c in "0123456789abcdef" for c in ks):
                records[ks] = ts
                continue
            # Legacy pipe-delimited: parse AND compute hash
            parts = ks.split("|")
            if len(parts) >= 5:
                records[(parts[0], parts[1], parts[3], parts[2], parts[4])] = ts
                import testplan as TP
                case = {"method": parts[0], "endpoint": parts[1],
                        "params": parts[2].split(",") if parts[2] else [],
                        "category": parts[3], "role": parts[4] if len(parts) > 4 else "",
                        "owner": parts[5] if len(parts) > 5 else "",
                        "accessor": parts[6] if len(parts) > 6 else ""}
                records[TP.case_id(case)] = ts
            elif len(parts) == 4:
                records[(parts[0], parts[1], parts[3], parts[2], "")] = ts
            elif len(parts) == 3:
                records[("*", parts[0], parts[2], parts[1], "")] = ts
            else:
                records[("*", ks, "", "", "")] = ts
        return records
    for t in tested or []:
        if isinstance(t, dict):
            m = t.get("method", "GET")
            u = t.get("url", "")
            c = t.get("vuln_class", "")
            p = ",".join(sorted(t.get("params") or []))
            records[(m, u, c, p, "")] = 0.0
        elif isinstance(t, str):
            parts = t.split("|")
            if len(parts) >= 5:
                records[(parts[0], parts[1], parts[3], parts[2], parts[4])] = 0.0
            elif len(parts) == 4:
                records[(parts[0], parts[1], parts[3], parts[2], "")] = 0.0
            elif len(parts) == 3:
                records[("*", parts[0], parts[2], parts[1], "")] = 0.0
            elif "||" in t:
                u, c = t.split("||", 1)
                records[("*", u, c, "", "")] = 0.0
            else:
                records[("*", t, "", "", "")] = 0.0
    return records


def _is_tested(method, url, vuln_class, tested_records, param="", role="", owner="", accessor=""):
    """Check if a specific case is tested. Uses case_id hash as primary lookup,
    falls back to legacy tuple match. No param/role fallback (prevents overclaim)."""
    import testplan as TP
    case = {"method": method, "endpoint": url, "params": [param] if param else [],
            "category": vuln_class, "role": role, "owner": owner, "accessor": accessor}
    hk = TP.case_id(case)
    if hk in tested_records:
        return True
    if (method, url, vuln_class, param, role) in tested_records:
        return True
    if ("*", url, vuln_class, param, role) in tested_records:
        return True
    return False


def _testplan_coverage(test_plan):
    """Extract coverage from test_plan cases. Returns {(method, url, category, param, role, owner, accessor): status}.
    Uses 7-tuple keys so different ownership scenarios cannot overwrite each other."""
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
        params = case.get("params") or []
        p = ",".join(sorted(params)) if params else ""
        role = case.get("role", "")
        owner = case.get("owner", "")
        accessor = case.get("accessor", "")
        covered[(m, u, c, p, role, owner, accessor)] = case.get("status", "pending")
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
        role = it.get("role", "")
        roles_seen.add(role or "default")

        v = by_class.setdefault(c, {"total": 0, "tested": 0, "endpoints": set()})
        v["total"] += 1
        v["endpoints"].add(u)
        param = it.get("param", "")
        owner = it.get("owner", "")
        accessor = it.get("accessor", "")
        is_covered = (_is_tested(m, u, c, tested_records, param=param, role=role,
                                 owner=owner, accessor=accessor) or
                      plan_cov.get((m, u, c, param, role, owner, accessor))
                      in ("tested", "confirmed", "disproved"))
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
            checks = tested_checks.get(f"{m}|{u}||{c}|", tested_checks.get(f"{m}|{u}||{c}", []))
            classes_detail[c] = {"status": status, "checks": checks,
                                 "roles_tested": sorted(op["roles"])}
        operations.append({"method": m, "url": u, "classes": classes_detail})

    leads = [{"url": x.get("url"), "class": x.get("vuln_class"),
              "severity": x.get("severity"), "proof_note": x.get("proof_note", "")}
             for x in cand]

    unique_tested = len(tested_records)

    # Class-level blind spot detection: vuln classes with hunt skills but zero test coverage
    _EXPECTED_CLASSES = {
        "idor", "xss", "sqli", "ssrf", "csrf", "cors", "open-redirect", "ssti",
        "xxe", "lfi", "rce", "race-condition", "http-smuggling", "auth-bypass",
        "business-logic", "file-upload", "prototype-pollution", "cache-poisoning",
        "deserialization", "jwt", "oauth", "mass-assignment", "privilege-escalation",
    }
    tested_classes = {c for c in by_class if by_class[c]["tested"] > 0}
    observed_classes = set(by_class.keys())
    blind_spots = sorted(_EXPECTED_CLASSES - tested_classes)

    return {"program": slug, "phase": d.get("phase"),
            "surface": len(surface), "tested": unique_tested,
            "security_tested": len(tested_checks),
            "candidates": len(cand), "confirmed": len(conf),
            "coverage_by_class": matrix,
            "coverage_by_role": role_coverage,
            "operations": operations[:50],
            "leads": leads,
            "blind_spots": blind_spots}


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

    if r.get("blind_spots"):
        L += ["", "  ## BLIND SPOTS (vuln classes never tested)"]
        L.append(f"  ⚠ {len(r['blind_spots'])} class(es) with hunt skills but zero coverage:")
        for bs in r["blind_spots"]:
            L.append(f"    - {bs}")

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
          "tested": {"GET|u1||idor|": 1.0, "POST|u1||idor|": 1.0},
          "tested_checks": {"GET|u1||idor|": ["horizontal_idor"], "GET|u1||idor": ["horizontal_idor"]},
          "candidates": [{"url": "u2", "vuln_class": "idor", "severity": "high",
                          "proof_note": "B read A order"}],
          "confirmed": [],
          "test_plan": {"cases": [
              {"method": "GET", "endpoint": "u3", "category": "bac", "role": "user_a", "status": "tested"},
              {"method": "GET", "endpoint": "u3", "category": "bac", "role": "user_b", "status": "tested"},
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
    # bac: 2 total — each role tested separately via per-role test_plan cases
    assert r["coverage_by_class"]["bac"]["total"] == 2, r["coverage_by_class"]["bac"]
    assert r["coverage_by_class"]["bac"]["tested"] == 2, r["coverage_by_class"]["bac"]
    # Exact coverage: a roleless plan case must NOT credit a role-specific surface item
    st2 = dict(st)
    st2["test_plan"] = {"cases": [
        {"method": "GET", "endpoint": "u3", "category": "bac", "status": "tested"},
    ]}
    json.dump(st2, open(os.path.join(base, "acme", "state.json"), "w"))
    r2 = report("acme", base)
    assert r2["coverage_by_class"]["bac"]["tested"] == 0, \
        f"roleless plan case must NOT credit role-specific surface: {r2['coverage_by_class']['bac']}"
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
