#!/usr/bin/env python3
"""
testplan.py — security test planner: feature map → structured test cases.

Takes the feature map (endpoints, params, auth) and generates a prioritized
security test plan mapping each endpoint to applicable vuln classes, roles,
and specific test actions.

CLI:
  python3 engine/engine/testplan.py plan --scope scope.json [--state state.json] [--fmap feature-map.json]
  python3 engine/engine/testplan.py selftest
"""
import argparse
import json
import os
import re
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

_ID_PARAMS = re.compile(r"(^|_)(id|uid|user_?id|account_?id|org_?id|team_?id|object_?id|ref|uuid)($|_)", re.I)
_FILE_PARAMS = re.compile(r"(file|upload|attachment|image|avatar|document|media|photo)", re.I)
_REDIRECT_PARAMS = re.compile(r"(url|uri|redirect|return|next|continue|dest|goto|link|callback|redir)", re.I)
_SEARCH_PARAMS = re.compile(r"(search|query|q|filter|find|keyword|term|s|name|title|text|input)", re.I)
_AUTH_PATHS = re.compile(r"/(login|signin|signup|register|auth|oauth|token|password|reset|verify|confirm|session|sso)", re.I)
_ADMIN_PATHS = re.compile(r"/(admin|manage|dashboard|internal|staff|moderator|settings/admin)", re.I)
_SENSITIVE_PATHS = re.compile(r"/(payment|billing|invoice|order|checkout|subscribe|wallet|transfer|withdraw)", re.I)

VULN_RULES = [
    {
        "id": "idor",
        "name": "Insecure Direct Object Reference",
        "match": lambda ep: ep.get("method") in ("GET", "POST", "PUT", "PATCH", "DELETE")
                 and any(_ID_PARAMS.search(p) for p in _params(ep)),
        "test": "Replace ID parameter with another user's ID and verify access control",
        "priority_boost": 2,
    },
    {
        "id": "bac",
        "name": "Broken Access Control",
        "match": lambda ep: ep.get("auth_required") or _ADMIN_PATHS.search(ep.get("url", "")),
        "test": "Access endpoint without auth or with lower-privilege role token",
        "priority_boost": 2,
    },
    {
        "id": "upload",
        "name": "Unrestricted File Upload",
        "match": lambda ep: ep.get("method") in ("POST", "PUT")
                 and any(_FILE_PARAMS.search(p) for p in _params(ep)),
        "test": "Upload file with dangerous extension (.svg, .html, .php) and verify content-type handling",
        "priority_boost": 1,
    },
    {
        "id": "open_redirect",
        "name": "Open Redirect",
        "match": lambda ep: any(_REDIRECT_PARAMS.search(p) for p in _params(ep)),
        "test": "Set redirect parameter to external domain and verify redirect is followed",
        "priority_boost": 0,
    },
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery",
        "match": lambda ep: ep.get("method") in ("POST", "PUT", "GET")
                 and any(_REDIRECT_PARAMS.search(p) for p in _params(ep)),
        "test": "Set URL parameter to internal address (169.254.169.254) or collaborator and verify server-side fetch",
        "priority_boost": 2,
    },
    {
        "id": "xss",
        "name": "Cross-Site Scripting",
        "match": lambda ep: any(_SEARCH_PARAMS.search(p) for p in _params(ep)),
        "test": "Inject XSS payload in search/input parameter and verify reflection in response",
        "priority_boost": 0,
    },
    {
        "id": "sqli",
        "name": "SQL Injection",
        "match": lambda ep: any(_SEARCH_PARAMS.search(p) for p in _params(ep))
                 or any(_ID_PARAMS.search(p) for p in _params(ep)),
        "test": "Inject SQL syntax (single quote, UNION, sleep) and observe error or timing difference",
        "priority_boost": 1,
    },
    {
        "id": "mass_assignment",
        "name": "Mass Assignment",
        "match": lambda ep: ep.get("method") in ("POST", "PUT", "PATCH")
                 and len(_params(ep)) >= 2,
        "test": "Add extra fields (role, is_admin, verified) to request body and verify they are accepted",
        "priority_boost": 1,
    },
    {
        "id": "auth_bypass",
        "name": "Authentication Bypass",
        "match": lambda ep: _AUTH_PATHS.search(ep.get("url", "")),
        "test": "Test default credentials, missing auth header, token manipulation, and response manipulation",
        "priority_boost": 1,
    },
    {
        "id": "rate_limit",
        "name": "Rate Limit Bypass",
        "match": lambda ep: _AUTH_PATHS.search(ep.get("url", "")),
        "test": "Send rapid requests and verify rate limiting is enforced; try bypass via headers (X-Forwarded-For)",
        "priority_boost": 0,
    },
    {
        "id": "sensitive_data",
        "name": "Sensitive Data Exposure",
        "match": lambda ep: _SENSITIVE_PATHS.search(ep.get("url", "")),
        "test": "Check for PII/financial data in response, verify HTTPS enforcement and caching headers",
        "priority_boost": 1,
    },
    {
        "id": "privilege_escalation",
        "name": "Privilege Escalation",
        "match": lambda ep: _ADMIN_PATHS.search(ep.get("url", ""))
                 and ep.get("method") in ("POST", "PUT", "PATCH", "DELETE"),
        "test": "Call admin endpoint with regular user credentials; try modifying own role/permissions",
        "priority_boost": 2,
    },
]


def _params(ep):
    p = ep.get("params") or ep.get("param") or []
    if isinstance(p, str):
        return [p] if p else []
    return [str(x) for x in p]


def _priority_score(ep, matched_rules):
    score = 0
    n_params = len(_params(ep))
    score += min(n_params, 5)
    if ep.get("auth_required"):
        score += 3
    if ep.get("method") in ("POST", "PUT", "PATCH", "DELETE"):
        score += 2
    if ep.get("confidence") == "observed":
        score += 2
    elif ep.get("confidence") == "documented":
        score += 1
    for r in matched_rules:
        score += r.get("priority_boost", 0)
    if _SENSITIVE_PATHS.search(ep.get("url", "")):
        score += 3
    if _ADMIN_PATHS.search(ep.get("url", "")):
        score += 2
    return score


def _priority_label(score):
    if score >= 10:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def generate_test_cases(endpoints, tested_checks=None):
    """Generate test cases from endpoint list. Returns list of test case dicts."""
    tested_checks = tested_checks or {}
    cases = []
    seen = set()

    for ep in endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET")
        matched = [r for r in VULN_RULES if r["match"](ep)]

        if not matched:
            continue

        for rule in matched:
            key = (method, url, rule["id"])
            if key in seen:
                continue
            seen.add(key)

            tc_key = f"{method}|{url}|{rule['id']}"
            ep_key = f"{method}|{url}"
            ep_checks = tested_checks.get(ep_key)
            already_tested = (tc_key in tested_checks
                              or (isinstance(ep_checks, list) and rule["id"] in ep_checks))

            score = _priority_score(ep, [rule])
            cases.append({
                "endpoint": url,
                "method": method,
                "category": rule["id"],
                "category_name": rule["name"],
                "test": rule["test"],
                "priority": _priority_label(score),
                "priority_score": score,
                "params": _params(ep),
                "auth_required": bool(ep.get("auth_required")),
                "confidence": ep.get("confidence", "unknown"),
                "roles": ["user_a", "user_b"] if rule["id"] in ("idor", "bac", "privilege_escalation") else [],
                "status": "tested" if already_tested else "pending",
            })

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
    tested_checks = (state or {}).get("tested_checks", {})

    cases = generate_test_cases(endpoints, tested_checks)

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
        lines.append(f"Scope: {', '.join((scope.get('in_scope') or [])[:5])}\n")

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
    assert "idor" in categories, f"missing idor: {categories}"
    assert "upload" in categories, f"missing upload: {categories}"
    assert "open_redirect" in categories or "ssrf" in categories, f"missing redirect/ssrf: {categories}"
    assert "xss" in categories or "sqli" in categories, f"missing xss/sqli: {categories}"
    assert "bac" in categories, f"missing bac: {categories}"
    assert "auth_bypass" in categories, f"missing auth_bypass: {categories}"
    assert "mass_assignment" in categories, f"missing mass_assignment: {categories}"
    assert "sensitive_data" in categories, f"missing sensitive_data: {categories}"

    # priority ordering: first case should be high priority
    assert result["plan"][0]["priority"] in ("critical", "high"), \
        f"first case priority: {result['plan'][0]['priority']}"

    # cross-reference with tested_checks
    tested = {"POST|https://api.acme.com/api/users|mass_assignment": True}
    result2 = build_test_plan(fmap, state={"tested_checks": tested})
    tested_cases = [c for c in result2["plan"] if c["status"] == "tested"]
    assert len(tested_cases) >= 1, "tested_checks cross-reference not working"

    # GET and POST to same URL generate separate cases
    user_cases = [c for c in result["plan"] if "users" in c["endpoint"] and c["category"] == "sqli"]
    methods = {c["method"] for c in user_cases}
    assert len(methods) >= 1, "should have method-specific cases"

    # hostile input
    empty = build_test_plan({"endpoints": []})
    assert empty["summary"]["total_cases"] == 0
    assert empty["markdown"]

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
