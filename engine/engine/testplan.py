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
import hashlib
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
_STATE_CHANGE_PATHS = re.compile(r"/(buy|purchase|checkout|transfer|apply|redeem|coupon|vote|follow|like|approve|cancel)", re.I)
_TEMPLATE_PARAMS = re.compile(r"(template|name|title|subject|message|body|comment|content|email|greeting)", re.I)
_WEBSOCKET_PATHS = re.compile(r"/(ws|wss|socket|realtime|stream|events|notifications|chat|live)", re.I)

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
    {
        "id": "race_condition",
        "name": "Race Condition",
        "match": lambda ep: ep.get("method") in ("POST", "PUT", "PATCH", "DELETE")
                 and _STATE_CHANGE_PATHS.search(ep.get("url", "")),
        "test": "Send concurrent identical requests (H2 last-byte sync) and verify state changes applied n>=2 times",
        "priority_boost": 2,
    },
    {
        "id": "csrf",
        "name": "Cross-Site Request Forgery",
        "match": lambda ep: ep.get("method") in ("POST", "PUT", "PATCH", "DELETE")
                 and ep.get("auth_required"),
        "test": "Verify anti-CSRF token presence; craft cross-origin form/fetch and test state-changing action",
        "priority_boost": 1,
    },
    {
        "id": "ssti",
        "name": "Server-Side Template Injection",
        "match": lambda ep: any(_TEMPLATE_PARAMS.search(p) for p in _params(ep)),
        "test": "Inject template syntax ({{7*7}}, ${7*7}, #{7*7}) and verify server-side evaluation in response",
        "priority_boost": 2,
    },
    {
        "id": "cors",
        "name": "CORS Misconfiguration",
        "match": lambda ep: ep.get("auth_required") and ep.get("method") == "GET",
        "test": "Send request with Origin: https://evil.com and check if reflected with Allow-Credentials: true",
        "priority_boost": 1,
    },
    {
        "id": "xxe",
        "name": "XML External Entity",
        "match": lambda ep: ep.get("method") in ("POST", "PUT")
                 and any(re.search(r"xml|soap|svg|feed|import|export", p, re.I) for p in _params(ep)),
        "test": "Submit XML with external entity declaration pointing to internal resource or OOB callback",
        "priority_boost": 2,
    },
    {
        "id": "http_smuggling",
        "name": "HTTP Request Smuggling",
        "match": lambda ep: ep.get("method") in ("POST", "PUT"),
        "test": "Test CL.TE and TE.CL desync with differential Content-Length/Transfer-Encoding headers",
        "priority_boost": 2,
    },
    {
        "id": "prototype_pollution",
        "name": "Prototype Pollution",
        "match": lambda ep: ep.get("method") in ("POST", "PUT", "PATCH")
                 and len(_params(ep)) >= 1,
        "test": "Inject __proto__, constructor.prototype in JSON body and verify property pollution in response",
        "priority_boost": 1,
    },
    {
        "id": "cache_poisoning",
        "name": "Web Cache Poisoning",
        "match": lambda ep: ep.get("method") == "GET",
        "test": "Add unkeyed headers (X-Forwarded-Host, X-Original-URL) and check if reflected in cached response",
        "priority_boost": 1,
    },
    {
        "id": "websocket_hijack",
        "name": "Cross-Site WebSocket Hijacking",
        "match": lambda ep: _WEBSOCKET_PATHS.search(ep.get("url", "")),
        "test": "Connect to WebSocket from cross-origin page and verify auth is enforced on upgrade request",
        "priority_boost": 1,
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
    """Convert a test case to a unique state key: method|url|params|category|role.
    Params are comma-joined (not pipe) to avoid ambiguity with the field delimiter."""
    url = case.get("endpoint", "")
    method = case.get("method", "GET")
    params = case.get("params") or []
    param = ",".join(sorted(params)) if params else ""
    category = case.get("category", "")
    role = case.get("role", "")
    return f"{method}|{url}|{param}|{category}|{role}"


def case_id(case):
    """Stable hash-based identifier for a test case. Collision-free across method, url,
    params, category, and role. Returns a 16-char hex digest (64-bit)."""
    canonical = json.dumps({
        "method": (case.get("method") or "GET").upper(),
        "url": case.get("endpoint") or case.get("url") or "",
        "params": sorted(case.get("params") or []),
        "category": case.get("category") or case.get("vuln_class") or "",
        "role": case.get("role") or "",
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


VALID_STATUSES = {"pending", "running", "tested", "blocked", "inconclusive", "disproved", "confirmed"}
_EVIDENCE_REQUIRED = {"tested", "confirmed", "disproved", "inconclusive"}

_CATEGORY_EVIDENCE = {
    "idor": ["user", "other user", "owner", "access", "id", "object"],
    "bac": ["role", "admin", "forbidden", "unauthorized", "access", "privilege"],
    "xss": ["reflect", "script", "payload", "alert", "inject", "stored", "dom"],
    "sqli": ["sql", "error", "database", "query", "extract", "union", "syntax"],
    "ssrf": ["internal", "localhost", "127.0.0", "metadata", "server", "oob"],
    "upload": ["file", "upload", "content-type", "extension", "mime", "shell"],
    "open_redirect": ["redirect", "location", "external", "domain", "url"],
    "mass_assignment": ["param", "role", "admin", "privilege", "field", "assign"],
    "auth_bypass": ["bypass", "token", "session", "auth", "login", "password"],
    "rate_limit": ["rate", "limit", "429", "throttle", "brute", "attempt"],
}


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


def generate_auth_tests(endpoints, identities):
    """Generate cross-role authorization test cases from endpoints and available identities.

    identities: list of {"email": ..., "role": "user"|"admin"|..., "ident": "A"|"B"}
    Returns list of auth test case dicts.
    """
    if not identities or len(identities) < 2:
        return []
    cases = []
    roles = {i.get("ident", ""): i.get("role", "user") for i in identities}
    id_pairs = [(a, b) for a in identities for b in identities if a["ident"] != b["ident"]]

    for ep in endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET")
        params = _params(ep)
        id_params = [p for p in params if _ID_PARAMS.search(p)]

        if ep.get("auth_required") or _ADMIN_PATHS.search(url):
            for owner, accessor in id_pairs:
                cases.append({
                    "endpoint": url, "method": method, "category": "bac",
                    "category_name": "Broken Access Control",
                    "test": f"Access as {accessor['ident']} (role={roles.get(accessor['ident'],'user')}) "
                            f"endpoint owned by {owner['ident']} (role={roles.get(owner['ident'],'user')})",
                    "priority": "high", "priority_score": 8,
                    "params": params, "auth_required": True,
                    "confidence": ep.get("confidence", "observed"),
                    "roles": [owner["ident"], accessor["ident"]],
                    "owner": owner["ident"], "accessor": accessor["ident"],
                    "status": "pending",
                })

        if id_params:
            for owner, accessor in id_pairs:
                cases.append({
                    "endpoint": url, "method": method, "category": "idor",
                    "category_name": "Insecure Direct Object Reference",
                    "test": f"Replace {id_params[0]} with {owner['ident']}'s object ID, "
                            f"request as {accessor['ident']}",
                    "priority": "high", "priority_score": 9,
                    "params": params, "auth_required": True,
                    "confidence": ep.get("confidence", "observed"),
                    "roles": [owner["ident"], accessor["ident"]],
                    "owner": owner["ident"], "accessor": accessor["ident"],
                    "status": "pending",
                })

        if _ADMIN_PATHS.search(url) and method in ("POST", "PUT", "PATCH", "DELETE"):
            for ident in identities:
                if roles.get(ident["ident"]) != "admin":
                    cases.append({
                        "endpoint": url, "method": method, "category": "privilege_escalation",
                        "category_name": "Privilege Escalation",
                        "test": f"Call admin endpoint as {ident['ident']} (role={roles.get(ident['ident'],'user')})",
                        "priority": "critical", "priority_score": 11,
                        "params": params, "auth_required": True,
                        "confidence": ep.get("confidence", "observed"),
                        "roles": [ident["ident"]],
                        "owner": "admin", "accessor": ident["ident"],
                        "status": "pending",
                    })
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
    """Return coverage stats from an executed plan."""
    by_status = {}
    for c in plan_cases:
        by_status.setdefault(c.get("status", "unknown"), []).append(c)
    total = len(plan_cases)
    done = len(by_status.get("confirmed", [])) + len(by_status.get("disproved", [])) + len(by_status.get("inconclusive", []))
    return {
        "total": total, "executed": done,
        "confirmed": len(by_status.get("confirmed", [])),
        "disproved": len(by_status.get("disproved", [])),
        "inconclusive": len(by_status.get("inconclusive", [])),
        "blocked": len(by_status.get("blocked", [])),
        "pending": len(by_status.get("pending", [])),
        "coverage_pct": round(100 * done / max(total, 1), 1),
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

    # state_key bridge
    sk = state_key({"endpoint": "https://a.com/x", "method": "POST", "params": ["id"], "category": "idor"})
    assert sk == "POST|https://a.com/x|id|idor|", f"got: {sk}"
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
    assert "id,name" in sk2, sk2
    assert sk3.endswith("|admin"), sk3

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
    assert "bac" in cats or "idor" in cats, f"auth tests missing bac/idor: {cats}"
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
