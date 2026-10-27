#!/usr/bin/env python3
"""
testplan.py — security test planner: feature map → structured test cases.

Takes the feature map (operations, inputs, actors, effects, and relationships)
and generates behavior-based cases with independent trust-dimensional outcomes.

CLI:
  python3 engine/engine/testplan.py plan --scope scope.json [--state state.json] [--fmap feature-map.json]
  python3 engine/engine/testplan.py selftest
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# VULN_RULES is kept as an empty list for backward compatibility.
# The engine no longer matches endpoints against a static vulnerability menu.
# Instead, each endpoint gets a dynamic analysis profile (see analyze_endpoint)
# and the hunt agent reasons about what to test from the profile.
VULN_RULES = []


def _params(ep):
    p = ep.get("params") or ep.get("param") or []
    if isinstance(p, str):
        return [p] if p else []
    if isinstance(p, dict):
        p = [p]
    return [str(x.get("name") or "unnamed") if isinstance(x, dict) else str(x)
            for x in p if x not in (None, "")]


def analyze_endpoint(ep):
    """Build a behavior profile and impact score without vulnerability-class rules."""
    import function_profile as FP
    function = ep.get("function_profile") or FP.from_endpoint(ep)
    url = ep.get("url", "")
    method = ep.get("method", "GET")
    params = _params(ep)
    score = FP.impact_score(function)
    priority = "critical" if score >= 65 else "high" if score >= 30 else "medium" if score >= 15 else "low"
    return {
        "url": url,
        "method": method,
        "params": params,
        "is_write": method in ("POST", "PUT", "PATCH", "DELETE"),
        "auth_required": bool(ep.get("auth_required")),
        "signals": list(function.get("trust_dimensions") or []),
        "function_profile": function,
        "priority_score": score,
        "priority": priority,
        "tags": ep.get("tags") or [],
        "category": ep.get("category", ""),
        "body_params": _params({"params": ep.get("body_params")}),
        "note": ep.get("note", ""),
        "source": ep.get("source", ""),
        "confidence": ep.get("confidence", "unknown"),
        "guidance": {},
        "guidance_text": "",
        "recommended_skills": [],
    }


def _build_test_instruction(profile):
    """Build a behavior-specific test instruction from the observed function."""
    method = profile.get("method", "GET")
    url = profile.get("url", "")
    signals = profile.get("signals", [])
    function = profile.get("function_profile") or {}
    parts = [f"{method} {url}",
             f"Action/resource: {function.get('action', 'unknown')} / {function.get('resource', 'unknown')}.",
             "Fetch a baseline and identify actors, owned data, state changes, and external effects.",
             "Form one hypothesis from the observed trust assumptions and execute it with exact controls."]
    if signals:
        parts.append("Untested trust dimensions: " + ", ".join(signals) + ".")
    if function.get("effects"):
        parts.append("Validate state changes and second-order effects independently; do not rely on status alone.")
    return " ".join(parts)


def generate_test_cases(endpoints, tested_checks=None):
    """Analyze endpoints and produce dynamic test profiles.

    No static vuln-class matching. Each endpoint gets an analysis profile
    with signals the hunt agent uses to form its own hypotheses.
    """
    tested_checks = tested_checks or {}
    cases = []
    seen = set()

    for ep in endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET")
        params = _params(ep)
        key = (method, url, tuple(sorted(params)), ep.get("role", ""),
               ep.get("owner", ""), ep.get("accessor", ""))
        if key in seen or not url:
            continue
        seen.add(key)

        profile = analyze_endpoint(ep)
        test_instruction = _build_test_instruction(profile)

        case = {
            "endpoint": url,
            "method": method,
            "category": "dynamic",
            "category_name": "Dynamic Analysis",
            "test": test_instruction,
            "priority": profile["priority"],
            "priority_score": profile["priority_score"],
            "params": params,
            "auth_required": profile["auth_required"],
            "confidence": profile["confidence"],
            "signals": profile["signals"],
            "trust_dimensions": list((profile.get("function_profile") or {}).get("trust_dimensions") or []),
            "function_profile": profile.get("function_profile") or {},
            "guidance_text": profile.get("guidance_text", ""),
            "recommended_skills": profile.get("recommended_skills", []),
            "roles": ["user_a", "user_b"] if profile["is_write"] and profile["auth_required"] else [],
            "role": ep.get("role", ""), "owner": ep.get("owner", ""),
            "accessor": ep.get("accessor", ""),
            "status": "pending",
        }
        case["case_id"] = case_id(case)
        if case["case_id"] in tested_checks or f"{method}|{url}" in tested_checks:
            case["status"] = "tested"
        if ep.get("unresolved_template") or "{" in url:
            case["status"] = "blocked"
            case["blocked_reason"] = "unresolved_path_template"
        if profile["is_write"] and profile["params"]:
            case["body"] = {p: f"<{p}>" for p in profile["params"][:10]}
        if ep.get("body_params"):
            case["body_params"] = profile["body_params"]
        cases.append(case)

    cases.sort(key=lambda c: -c["priority_score"])
    return cases


def build_test_plan(feature_map, state=None, scope=None):
    """Build a complete test plan from feature map data.

    feature_map: dict from build_feature_map() or loaded feature-map.json
    state: engagement state dict (for tested_checks cross-reference)
    scope: scope dict (for context)

    Returns {"plan": [test_cases], "summary": {stats}, "markdown": str}
    """
    if isinstance(feature_map, str):
        feature_map = json.loads(feature_map)

    endpoints = feature_map.get("endpoints", [])
    tested_checks = (state or {}).get("tested") or (state or {}).get("tested_checks", {})

    cases = generate_test_cases(endpoints, tested_checks)

    # Integrate ownership/authorization test cases when identities are available
    identities = feature_map.get("identities") or []
    if identities:
        auth_cases = generate_auth_tests(endpoints, identities)
        existing_ids = {state_key(c) for c in cases}
        for ac in auth_cases:
            sk = state_key(ac)
            if sk not in existing_ids:
                cases.append(ac)
                existing_ids.add(sk)

    by_category = {}
    for c in cases:
        by_category.setdefault(c["category"], []).append(c)

    by_priority = {}
    for c in cases:
        by_priority.setdefault(c["priority"], []).append(c)

    n_tested = sum(1 for c in cases if c["status"] == "tested")
    n_pending = sum(1 for c in cases if c["status"] == "pending")

    summary = {
        "total_cases": len(cases),
        "tested": n_tested,
        "pending": n_pending,
        "coverage_pct": round(100 * n_tested / max(len(cases), 1), 1),
        "by_category": {k: len(v) for k, v in sorted(by_category.items())},
        "by_priority": {k: len(v) for k, v in sorted(by_priority.items(),
                        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 9))},
        "endpoints_covered": len({(c["method"], c["endpoint"]) for c in cases}),
        "total_endpoints": len(endpoints),
    }

    md = _render_markdown(cases, summary, feature_map.get("slug", "unknown"), scope)

    return {"plan": cases, "summary": summary, "markdown": md}


def _render_markdown(cases, summary, slug, scope=None):
    lines = [f"# Security Test Plan — {slug}\n",
             f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}  ",
             f"Total test cases: {summary['total_cases']} "
             f"({summary['tested']} tested, {summary['pending']} pending, "
             f"{summary['coverage_pct']}% coverage)\n"]

    if scope:
        ins = getattr(scope, 'in_scope', None) or (scope.get('in_scope') if isinstance(scope, dict) else []) or []
        lines.append(f"Scope: {', '.join(ins[:5])}\n")

    lines.append("## Priority Distribution\n")
    for pri in ("critical", "high", "medium", "low"):
        n = summary["by_priority"].get(pri, 0)
        if n:
            bar = "#" * min(n, 40)
            lines.append(f"  {pri:8s}  {bar} {n}")
    lines.append("")

    lines.append("## Test Cases by Category\n")
    by_cat = {}
    for c in cases:
        by_cat.setdefault(c["category_name"], []).append(c)

    for cat_name, cat_cases in sorted(by_cat.items()):
        pending = sum(1 for c in cat_cases if c["status"] == "pending")
        tested = sum(1 for c in cat_cases if c["status"] == "tested")
        lines.append(f"### {cat_name} ({len(cat_cases)} cases, {tested} tested, {pending} pending)\n")

        lines.append("| Priority | Method | Endpoint | Params | Status |")
        lines.append("|----------|--------|----------|--------|--------|")
        for c in cat_cases[:25]:
            params_str = ", ".join(c["params"][:3])
            if len(c["params"]) > 3:
                params_str += f" +{len(c['params'])-3}"
            status_mark = "done" if c["status"] == "tested" else "TODO"
            lines.append(f"| {c['priority']:8s} | {c['method']:6s} | `{c['endpoint'][:60]}` | {params_str} | {status_mark} |")
        if len(cat_cases) > 25:
            lines.append(f"| ... | | | | {len(cat_cases)-25} more |")
        lines.append("")

    lines.append("## Coverage Summary\n")
    lines.append(f"- Endpoints with test cases: {summary['endpoints_covered']}/{summary['total_endpoints']}")
    lines.append(f"- Test coverage: {summary['coverage_pct']}%")
    lines.append(f"- Categories tested: {', '.join(k for k, v in summary['by_category'].items())}")
    lines.append("")

    return "\n".join(lines)


def state_key(case):
    """Human-readable state key (for logging/debugging). Primary identity is case_id()."""
    url = case.get("endpoint", "")
    method = case.get("method", "GET")
    params = _params(case)
    param = ",".join(sorted(params)) if params else ""
    category = case.get("category", "")
    role = case.get("role", "")
    owner = case.get("owner", "")
    accessor = case.get("accessor", "")
    return f"{method}|{url}|{param}|{category}|{role}|{owner}|{accessor}"


def case_id(case):
    """Stable hash-based identifier for a test case. Collision-free across method, url,
    params, category, role, owner, and accessor. Returns a 16-char hex digest (64-bit).
    This is the PRIMARY key used in state, coverage, and plan index."""
    canonical = json.dumps({
        "accessor": case.get("accessor") or "",
        "category": case.get("category") or case.get("vuln_class") or "",
        "method": (case.get("method") or "GET").upper(),
        "owner": case.get("owner") or "",
        "params": sorted(_params(case)),
        "role": case.get("role") or "",
        "url": case.get("endpoint") or case.get("url") or "",
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


VALID_STATUSES = {"pending", "running", "tested", "blocked", "inconclusive", "disproved", "confirmed"}
_EVIDENCE_REQUIRED = {"tested", "confirmed", "disproved", "inconclusive"}

_CATEGORY_EVIDENCE = {}


def validate_evidence(status, evidence, category=None):
    """Check evidence meets requirements for the given status. Returns (ok, reason)."""
    if status not in _EVIDENCE_REQUIRED:
        return True, ""
    if not evidence or not str(evidence).strip():
        return False, f"status '{status}' requires evidence"
    ev = str(evidence).lower()
    if status == "confirmed":
        has_req = any(k in ev for k in ("request", "http", "curl", "post ", "get ", "put ",
                                        "burp", "response", "status"))
        has_impact = any(k in ev for k in ("leaked", "accessed", "modified", "created",
                                           "deleted", "executed", "returned", "vulnerable",
                                           "injection", "bypass", "takeover", "exfiltrat"))
        if not (has_req and has_impact):
            return False, "confirmed findings must include both request evidence AND demonstrated impact"
        if category and category in _CATEGORY_EVIDENCE:
            cat_kw = _CATEGORY_EVIDENCE[category]
            if not any(k in ev for k in cat_kw):
                return False, f"'{category}' confirmation should reference: {', '.join(cat_kw[:3])}"
    if status == "disproved":
        has_defense = any(k in ev for k in ("403", "401", "denied", "blocked", "rejected",
                                            "not found", "no access", "forbidden"))
        if not has_defense:
            return False, "disproved results must describe the defensive response observed"
    return True, ""


def resume_plan(plan_cases):
    """Reset any 'running' cases back to 'pending' (for interrupted plans)."""
    reset = 0
    for case in (plan_cases or []):
        if case.get("status") == "running":
            case["status"] = "pending"
            case.pop("executed_at", None)
            reset += 1
    return reset


def mark_case(case, status, evidence=None):
    """Update a test case with execution results. Enforces evidence requirements."""
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status!r}, must be one of {VALID_STATUSES}")
    ok, reason = validate_evidence(status, evidence)
    if not ok:
        raise ValueError(reason)
    case["status"] = status
    case["executed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if evidence:
        case["evidence"] = evidence
    return case


DIMENSION_STATUSES = {"tested", "confirmed", "disproved", "inconclusive", "blocked"}


def apply_hypothesis_results(case, results, evidence_dir=None, case_key=None):
    """Persist per-dimension outcomes, accepting terminal results only with matching observations."""
    applicable = set(case.get("trust_dimensions") or
                     (case.get("function_profile") or {}).get("trust_dimensions") or [])
    ledger = case.setdefault("hypothesis_ledger", [])
    dimension_results = case.setdefault("dimension_results", {})
    accepted = 0
    for raw in results or []:
        if not isinstance(raw, dict):
            continue
        dimensions = raw.get("dimensions") or [raw.get("dimension")]
        hypothesis = str(raw.get("hypothesis") or "").strip()
        observation_ids = [str(value) for value in raw.get("observation_ids") or [] if value]
        evidence = str(raw.get("evidence") or raw.get("reason") or "").strip()
        status = str(raw.get("status") or "inconclusive").lower()
        observations = []
        if evidence_dir and case_key and observation_ids:
            import evidence as EV
            requested = set(observation_ids)
            observations = [obs for obs in EV.get_observations(evidence_dir, case_id=case_key)
                            if obs.get("id") in requested and obs.get("resp_status", 0) != 0]
        for dimension in dimensions:
            if dimension not in applicable:
                continue
            record = {"hypothesis": hypothesis, "status": status, "observation_ids": observation_ids,
                      "evidence": evidence, "ts": time.time()}
            if len(dimensions) != 1:
                record["status"] = "blocked"
                record["reason"] = "exactly one trust dimension per hypothesis result is required"
            elif status not in DIMENSION_STATUSES or not hypothesis or not evidence:
                record["status"] = "blocked"
                record["reason"] = "hypothesis, valid status, and evidence/reason are required"
            elif status == "blocked":
                record["reason"] = evidence
            elif not observations:
                record["status"] = "blocked"
                record["reason"] = "missing or mismatched transport observations"
            else:
                accepted += 1
            ledger.append(dict(record, dimension=dimension, case_id=case_key or case.get("case_id")))
            dimension_results[dimension] = record
    return {"accepted": accepted, "recorded": len(ledger)}


def generate_auth_tests(endpoints, identities):
    """Generate actor/role/tenant boundary cases from observed authenticated functions."""
    if not identities or len(identities) < 2:
        return []
    cases = []
    roles = {i.get("ident", ""): i.get("role", "user") for i in identities}
    pairs = [(a, b) for a in identities for b in identities if a["ident"] != b["ident"]]
    for ep in endpoints:
        if not ep.get("auth_required"):
            continue
        url = ep.get("url", "")
        method = ep.get("method", "GET")
        params = _params(ep)
        function = analyze_endpoint(ep)["function_profile"]
        for owner, accessor in pairs:
            case = {
                "endpoint": url, "method": method, "category": "boundary",
                "category_name": "Actor and Resource Boundary",
                "test": (f"Run the same operation as {accessor['ident']} and compare data/state against "
                         f"{owner['ident']}; require owner-specific proof, not response similarity"),
                "priority": "high", "priority_score": 45,
                "params": params, "auth_required": True,
                "confidence": ep.get("confidence", "observed"),
                "roles": [owner["ident"], accessor["ident"]],
                "owner": owner["ident"], "accessor": accessor["ident"],
                "role": roles.get(accessor["ident"], "user"),
                "function_profile": function,
                "trust_dimensions": ["actor_variation", "ownership_boundary"],
                "status": "pending",
            }
            if method in ("POST", "PUT", "PATCH", "DELETE") and params:
                case["body"] = {p: f"<{p}>" for p in params[:10]}
            cases.append(case)
    for case in cases:
        case["case_id"] = case_id(case)
    return cases


def execute_plan(plan_cases, state, run_test_fn=None):
    """Execute pending test cases from a plan.

    run_test_fn(case) -> {"status": "confirmed"|"disproved"|"inconclusive"|"blocked",
                          "evidence": str}
    If run_test_fn is None, returns the plan unchanged (plan-only mode).
    """
    if not run_test_fn:
        return plan_cases

    state.setdefault("tested_checks", {})
    max_consecutive_failures = int(os.environ.get("HUNT_MAX_CONSECUTIVE_FAILURES", "3"))
    consecutive_failures = 0
    for case in plan_cases:
        if case.get("status") != "pending":
            continue
        if consecutive_failures >= max_consecutive_failures:
            case["status"] = "blocked"
            case["evidence"] = f"blocked: {consecutive_failures} consecutive failures — stopping"
            continue
        case["status"] = "running"
        try:
            result = run_test_fn(case)
            status = result.get("status", "inconclusive") if result else "inconclusive"
            evidence = result.get("evidence") if result else None
            ok, reason = validate_evidence(status, evidence, category=case.get("category"))
            if not ok:
                status = "inconclusive"
                evidence = (evidence or "") + f" [evidence insufficient: {reason}]"
            mark_case(case, status, evidence)
            consecutive_failures = 0
        except Exception as e:
            consecutive_failures += 1
            mark_case(case, "blocked", f"exception: {e}")

        sk = state_key(case)
        ep_key = f"{case.get('method','GET')}|{case.get('endpoint','')}"
        state["tested_checks"].setdefault(ep_key, [])
        if case["category"] not in state["tested_checks"][ep_key]:
            state["tested_checks"][ep_key].append(case["category"])

    return plan_cases


def pending_cases(plan_cases, priority=None):
    """Return pending test cases, optionally filtered by priority."""
    cases = [c for c in plan_cases if c.get("status") == "pending"]
    if priority:
        cases = [c for c in cases if c.get("priority") == priority]
    return cases


def plan_coverage(plan_cases):
    """Return case and independent trust-dimensional coverage from an executed plan."""
    by_status = {}
    dimensions = {}
    for case in plan_cases:
        by_status.setdefault(case.get("status", "unknown"), []).append(case)
        applicable = case.get("trust_dimensions") or (case.get("function_profile") or {}).get("trust_dimensions") or []
        results = case.get("dimension_results") or {}
        for name in applicable:
            status = (results.get(name) or {}).get("status", "unknown")
            rec = dimensions.setdefault(name, {"total": 0, "tested": 0, "confirmed": 0,
                                               "disproved": 0, "inconclusive": 0, "blocked": 0,
                                               "pending": 0, "unknown": 0})
            rec["total"] += 1
            rec[status if status in rec else "unknown"] += 1
            if status in ("tested", "confirmed", "disproved"):
                rec["tested"] += 1
    total = len(plan_cases)
    done = sum(len(by_status.get(status, [])) for status in ("tested", "confirmed", "disproved", "inconclusive"))
    dimension_total = sum(rec["total"] for rec in dimensions.values())
    dimension_tested = sum(rec["tested"] for rec in dimensions.values())
    return {
        "total": total, "executed": done,
        "confirmed": len(by_status.get("confirmed", [])),
        "disproved": len(by_status.get("disproved", [])),
        "inconclusive": len(by_status.get("inconclusive", [])),
        "blocked": len(by_status.get("blocked", [])),
        "pending": len(by_status.get("pending", [])),
        "coverage_pct": round(100 * done / max(total, 1), 1),
        "dimensions": dimensions,
        "dimension_total": dimension_total,
        "dimension_tested": dimension_tested,
        "dimension_coverage_pct": round(100 * dimension_tested / max(dimension_total, 1), 1),
        "blind_spots": sorted(name for name, rec in dimensions.items() if rec["tested"] < rec["total"]),
    }


# ---------------------------------------------------------------- CLI

def _cmd_plan(a):
    scope_path = os.path.expanduser(a.scope)
    scope = json.load(open(scope_path))
    slug = scope.get("name", os.path.basename(scope_path).replace(".json", ""))

    state = {}
    if a.state and os.path.isfile(os.path.expanduser(a.state)):
        state = json.load(open(os.path.expanduser(a.state)))

    fmap_path = a.fmap
    if not fmap_path:
        eng_dir = os.path.join(os.path.expanduser(a.base), slug)
        fmap_path = os.path.join(eng_dir, "feature-map.json")

    if os.path.isfile(fmap_path):
        fmap = json.load(open(fmap_path))
    else:
        import featuremap as FM
        fmap = FM.build_feature_map(slug, base=a.base, state=state)

    result = build_test_plan(fmap, state=state, scope=scope)
    print(result["markdown"])

    out = os.path.join(os.path.expanduser(a.base), slug, "test-plan.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"plan": result["plan"], "summary": result["summary"]}, f, indent=2)
    print(f"\nSaved {len(result['plan'])} test cases to {out}")
    return 0


def _selftest(_a=None):
    mock_endpoints = [
        {"url": "https://api.acme.com/api/users", "method": "GET", "params": ["id", "search"],
         "confidence": "observed", "source": "burp"},
        {"url": "https://api.acme.com/api/users", "method": "POST", "params": ["name", "email", "role"],
         "confidence": "observed", "source": "burp", "auth_required": True},
        {"url": "https://api.acme.com/api/users/profile", "method": "PUT",
         "params": ["user_id", "name", "avatar"], "confidence": "observed", "source": "burp",
         "auth_required": True},
        {"url": "https://api.acme.com/api/files/upload", "method": "POST",
         "params": ["file", "description"], "confidence": "observed", "source": "burp"},
        {"url": "https://api.acme.com/login", "method": "POST", "params": ["email", "password"],
         "confidence": "observed", "source": "burp"},
        {"url": "https://api.acme.com/api/redirect", "method": "GET", "params": ["url"],
         "confidence": "documented", "source": "profile"},
        {"url": "https://api.acme.com/admin/settings", "method": "POST", "params": ["config"],
         "confidence": "observed", "source": "burp", "auth_required": True},
        {"url": "https://api.acme.com/api/payment/charge", "method": "POST",
         "params": ["amount", "card_id"], "confidence": "observed", "source": "burp",
         "auth_required": True},
        {"url": "https://api.acme.com/api/search", "method": "GET", "params": ["q"],
         "confidence": "inferred", "source": "js"},
    ]

    fmap = {"slug": "acme", "endpoints": mock_endpoints, "total_endpoints": len(mock_endpoints)}
    result = build_test_plan(fmap)

    assert result["plan"], "no test cases generated"
    assert result["summary"]["total_cases"] > 0
    assert result["summary"]["pending"] > 0
    assert result["markdown"]

    categories = {c["category"] for c in result["plan"]}
    assert "dynamic" in categories, f"expected dynamic category: {categories}"

    # dynamic profiles should carry signals from the mock endpoints
    all_signals = set()
    for c in result["plan"]:
        all_signals.update(c.get("signals", []))
    assert "actor_variation" in all_signals, f"missing actor dimension: {all_signals}"
    assert "input_variation" in all_signals, f"missing input dimension: {all_signals}"
    assert "state_and_sequence" in all_signals, f"missing state dimension: {all_signals}"
    with_body = analyze_endpoint({"url": "https://api.acme.com/api/users", "method": "POST",
                                  "params": ["name"], "body_params": ["role"], "role": "member"})
    assert "content_and_parser_variation" in with_body["signals"], with_body["signals"]
    assert "role_transition" in with_body["signals"], with_body["signals"]

    # priority ordering: first case should be high priority
    assert result["plan"][0]["priority"] in ("critical", "high"), \
        f"first case priority: {result['plan'][0]['priority']}"

    # cross-reference with tested_checks
    tested = {"POST|https://api.acme.com/api/users": True}
    result2 = build_test_plan(fmap, state={"tested_checks": tested})
    tested_cases = [c for c in result2["plan"] if c["status"] == "tested"]
    assert len(tested_cases) >= 1, "tested_checks cross-reference not working"

    # multiple endpoints produce separate cases
    endpoints_seen = {c["endpoint"] for c in result["plan"]}
    assert len(endpoints_seen) >= 4, f"expected multiple endpoints: {endpoints_seen}"

    # hostile input
    empty = build_test_plan({"endpoints": []})
    assert empty["summary"]["total_cases"] == 0
    assert empty["markdown"]

    # state_key bridge
    sk = state_key({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor"})
    assert sk == "POST|https://a.com/x|id|idor|||", f"got: {sk}"
    # multi-param + role: keys must not collide
    sk2 = state_key({"endpoint": "https://a.com/x", "method": "POST", "params": ["id", "name"], "category": "idor"})
    sk3 = state_key({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor", "role": "admin"})
    assert sk2 != sk, "multi-param key must differ from single-param"
    assert sk3 != sk, "role key must differ from no-role"

    # case_id: stable hash, collision-free
    cid1 = case_id({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor"})
    cid2 = case_id({"endpoint": "https://a.com/x", "method": "POST", "params": ["id", "name"], "category": "idor"})
    cid3 = case_id({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor", "role": "admin"})
    cid4 = case_id({"endpoint": "https://a.com/x", "method": "GET", "params": ["id"], "category": "idor"})
    assert len(cid1) == 16 and all(c in "0123456789abcdef" for c in cid1), f"bad case_id format: {cid1}"
    assert cid1 != cid2, "multi-param case_id must differ"
    assert cid1 != cid3, "role case_id must differ"
    assert cid1 != cid4, "method case_id must differ"
    # param order doesn't matter
    cid5 = case_id({"endpoint": "https://a.com/x", "method": "POST", "params": ["name", "id"], "category": "idor"})
    assert cid2 == cid5, "param order must not affect case_id"
    # url/endpoint aliases produce same id
    cid6 = case_id({"url": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor"})
    assert cid1 == cid6, "url and endpoint must produce same case_id"
    # owner/accessor collision avoidance
    cid7 = case_id({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor", "owner": "A", "accessor": "B"})
    cid8 = case_id({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor", "owner": "B", "accessor": "A"})
    assert cid7 != cid8, "A/B vs B/A must produce different case_ids"
    assert cid7 != cid1, "owner/accessor case must differ from unscoped"
    assert "id,name" in sk2, sk2
    assert "|admin|" in sk3, sk3

    # execute_plan with mock runner (evidence must pass validation)
    import copy
    plan = copy.deepcopy(result["plan"])
    st = {}
    def mock_runner(case):
        cat = case.get("category", "")
        ev = "HTTP POST request to /api/users returned 200 — "
        if cat == "idor":
            ev += "accessed other user's object with different owner id"
        elif cat == "bac":
            ev += "non-admin role accessed admin endpoint, privilege escalation"
        elif cat == "xss":
            ev += "reflected script payload in response body"
        elif cat == "sqli":
            ev += "SQL syntax error in database query response"
        elif cat == "mass_assignment":
            ev += "role param accepted, privilege escalated via field assignment"
        elif cat == "sensitive_data":
            ev += "response leaked user PII data"
        elif cat == "auth_bypass":
            ev += "bypass auth token validation, session accessed"
        elif cat in ("open_redirect", "ssrf"):
            ev += "redirect to external domain location confirmed"
        elif cat == "upload":
            ev += "file upload with shell extension accepted"
        elif cat == "rate_limit":
            ev += "no rate limit after 100 attempts, brute throttle missing"
        else:
            ev += "response returned sensitive data accessed"
        return {"status": "confirmed", "evidence": ev}
    execute_plan(plan, st, run_test_fn=mock_runner)
    confirmed = [c for c in plan if c["status"] == "confirmed"]
    assert len(confirmed) > 0, "execute_plan didn't run any cases"
    assert "request" in confirmed[0].get("evidence", "").lower()
    assert confirmed[0].get("executed_at")
    assert st.get("tested_checks"), "tested_checks not updated"

    # resume_plan resets running → pending
    running_plan = [{"status": "running"}, {"status": "confirmed"}, {"status": "pending"}]
    n = resume_plan(running_plan)
    assert n == 1 and running_plan[0]["status"] == "pending"
    assert running_plan[1]["status"] == "confirmed"  # untouched

    # plan_coverage
    cov = plan_coverage(plan)
    assert cov["confirmed"] > 0
    assert cov["pending"] == 0
    assert cov["coverage_pct"] == 100.0

    # pending_cases filter
    plan2 = [{"status": "pending", "priority": "high"}, {"status": "pending", "priority": "low"},
             {"status": "confirmed", "priority": "high"}]
    assert len(pending_cases(plan2)) == 2
    assert len(pending_cases(plan2, priority="high")) == 1

    # validate_evidence enforcement
    ok, _ = validate_evidence("confirmed", "just a number 200")
    assert not ok, "confirmed without request/impact should fail"
    ok, _ = validate_evidence("confirmed", "HTTP request returned leaked data")
    assert ok, "valid confirmed evidence should pass"
    ok, _ = validate_evidence("disproved", "server returned 403 forbidden")
    assert ok
    ok, _ = validate_evidence("disproved", "nothing happened")
    assert not ok, "disproved without defensive response should fail"
    ok, _ = validate_evidence("tested", "checked endpoint, no issues")
    assert ok
    ok, _ = validate_evidence("tested", "")
    assert not ok

    # mark_case rejects invalid status
    try:
        mark_case({"status": "pending"}, "bogus")
        assert False, "should have raised"
    except ValueError:
        pass

    # generate_auth_tests
    identities = [
        {"ident": "A", "role": "user", "email": "a@test.com"},
        {"ident": "B", "role": "user", "email": "b@test.com"},
    ]
    auth_cases = generate_auth_tests(mock_endpoints, identities)
    assert len(auth_cases) > 0, "no auth test cases generated"
    cats = {c["category"] for c in auth_cases}
    assert cats == {"boundary"}, f"auth tests must be behavior boundaries: {cats}"
    assert all(c.get("owner") and c.get("accessor") for c in auth_cases)
    assert generate_auth_tests([], []) == []  # no identities -> empty

    # consecutive failure blocking
    fail_count = [0]
    def failing_runner(case):
        fail_count[0] += 1
        raise RuntimeError("mock failure")
    plan3 = [{"status": "pending", "priority": "high", "endpoint": f"/ep{i}",
              "method": "GET", "category": "xss", "params": []}
             for i in range(6)]
    os.environ["HUNT_MAX_CONSECUTIVE_FAILURES"] = "3"
    execute_plan(plan3, {}, run_test_fn=failing_runner)
    blocked = [c for c in plan3 if c["status"] == "blocked"]
    assert len(blocked) >= 3, f"consecutive failure blocking not working: {[c['status'] for c in plan3]}"
    os.environ.pop("HUNT_MAX_CONSECUTIVE_FAILURES", None)

    print("testplan.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="security test planner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("plan", help="Generate test plan from feature map")
    pp.add_argument("--scope", required=True, help="scope.json path")
    pp.add_argument("--state", default=None, help="state.json path")
    pp.add_argument("--fmap", default=None, help="feature-map.json path (auto-detected if omitted)")
    pp.add_argument("--base", default=DEFAULT_BASE)
    pp.set_defaults(fn=_cmd_plan)

    sub.add_parser("selftest").set_defaults(fn=_selftest)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
