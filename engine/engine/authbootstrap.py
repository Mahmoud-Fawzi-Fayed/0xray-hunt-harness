#!/usr/bin/env python3
"""
authbootstrap.py — pre-hunt authenticated access bootstrap.

Analyzes discovery output and produces an account setup plan:
what accounts are needed, what roles, what the priority order is.
Then orchestrates authsession.py to provision them.

This solves the #1 blocker from real hunts: testing stalls because
the harness mapped the surface but never got authenticated access.
"""
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def analyze_auth_needs(surface, scope=None):
    """Analyze the discovered surface and determine what accounts are needed.

    Returns a plan dict:
    {
        "accounts_needed": [
            {"role": "user_a", "purpose": "primary test account", "priority": "critical"},
            {"role": "user_b", "purpose": "cross-account IDOR testing", "priority": "critical"},
            ...
        ],
        "auth_hosts": ["login.example.com", ...],
        "auth_walled_endpoints": N,
        "total_endpoints": N,
        "auth_coverage_pct": float,
        "recommendations": [str, ...]
    }
    """
    total = len(surface)
    auth_walled = [s for s in surface if s.get("auth_required")]
    write_endpoints = [s for s in surface if s.get("method", "GET") in ("POST", "PUT", "PATCH", "DELETE")]
    has_identity = [s for s in surface
                    if any(re.search(r'(id|uid|user_?id|account_?id|org_?id)', p, re.I)
                           for p in (s.get("params") or []))]

    auth_hosts = set()
    for s in surface:
        url = s.get("url", "")
        if re.search(r'/(login|signin|signup|register|auth|oauth|session|sso)', url, re.I):
            from urllib.parse import urlparse
            host = urlparse(url).hostname
            if host:
                auth_hosts.add(host)

    accounts = []
    recommendations = []

    # Always need at least two accounts for cross-account testing
    accounts.append({
        "role": "user_a",
        "purpose": "Primary test account — victim in cross-account tests",
        "priority": "critical",
    })
    accounts.append({
        "role": "user_b",
        "purpose": "Attacker account — cross-account IDOR/BAC testing",
        "priority": "critical",
    })

    # Detect org/team structures
    has_org = any(re.search(r'(org|team|workspace|company|tenant)', s.get("url", ""), re.I) for s in surface)
    if has_org:
        accounts.append({
            "role": "org_admin",
            "purpose": "Org admin — test role escalation and admin boundary",
            "priority": "high",
        })
        accounts.append({
            "role": "org_member",
            "purpose": "Org viewer/member — test vertical escalation",
            "priority": "high",
        })
        recommendations.append("Create an organization with user_a as admin, invite user_b as viewer/member")

    # Detect admin paths
    has_admin = any(re.search(r'/(admin|manage|dashboard|internal|staff)', s.get("url", ""), re.I) for s in surface)
    if has_admin:
        recommendations.append("Check if admin access is available via dev/sandbox — needed for admin endpoint testing")

    # Detect role-differentiated endpoints
    has_roles = any(re.search(r'(role|permission|scope|grant)', s.get("url", "") + " ".join(s.get("params", [])), re.I)
                    for s in surface)
    if has_roles:
        recommendations.append("Enumerate all role types from API docs/responses — create one account per role")

    # Detect API key endpoints
    has_api_keys = any(re.search(r'(api.?key|token|credential|secret)', s.get("url", ""), re.I) for s in surface)
    if has_api_keys:
        recommendations.append("Generate API keys from both accounts — test cross-account key use")

    # Coverage assessment
    auth_pct = (len(auth_walled) / total * 100) if total else 0

    if auth_pct > 50:
        recommendations.insert(0, f"CRITICAL: {len(auth_walled)}/{total} endpoints ({auth_pct:.0f}%) require auth — "
                                   "provisioning accounts is BLOCKING for effective testing")
    elif auth_pct > 20:
        recommendations.insert(0, f"{len(auth_walled)}/{total} endpoints ({auth_pct:.0f}%) require auth — "
                                   "account setup is high priority")

    if has_identity and write_endpoints:
        recommendations.append(f"{len(has_identity)} endpoints handle object IDs + {len(write_endpoints)} "
                               "write endpoints — cross-account mutation testing is highest-value")

    return {
        "accounts_needed": accounts,
        "auth_hosts": sorted(auth_hosts),
        "auth_walled_endpoints": len(auth_walled),
        "total_endpoints": total,
        "auth_coverage_pct": round(auth_pct, 1),
        "write_endpoints": len(write_endpoints),
        "identity_endpoints": len(has_identity),
        "has_org_structure": has_org,
        "recommendations": recommendations,
    }


def format_plan(plan):
    """Format the auth plan as readable markdown."""
    lines = ["# Authentication Bootstrap Plan", ""]

    lines.append(f"**Surface:** {plan['total_endpoints']} endpoints total, "
                 f"{plan['auth_walled_endpoints']} require auth ({plan['auth_coverage_pct']}%)")
    lines.append(f"**Write endpoints:** {plan['write_endpoints']} | "
                 f"**Identity endpoints:** {plan['identity_endpoints']}")
    lines.append("")

    if plan["auth_hosts"]:
        lines.append(f"**Auth hosts:** {', '.join(plan['auth_hosts'])}")
        lines.append("")

    lines.append("## Accounts Needed")
    lines.append("")
    for acc in plan["accounts_needed"]:
        lines.append(f"- **{acc['role']}** [{acc['priority']}] — {acc['purpose']}")
    lines.append("")

    if plan["recommendations"]:
        lines.append("## Recommendations")
        lines.append("")
        for r in plan["recommendations"]:
            lines.append(f"- {r}")
        lines.append("")

    slug = plan.get("slug", "<slug>")
    lines.append("## Setup Steps")
    lines.append("")
    lines.append("### Automated (if signup is not Cloudflare-protected)")
    lines.append(f"1. Run: `python3 engine/engine/authsession.py provision --program {slug}`")
    lines.append(f"2. Verify: `python3 engine/engine/authsession.py show --program {slug}`")
    lines.append("")
    lines.append("### Manual (if Cloudflare or CAPTCHA blocks automated signup)")
    lines.append("1. Create user_a account in your browser (use H1-registered email)")
    lines.append("2. Create user_b account (different email, same platform)")
    lines.append("3. Open DevTools → Application → Cookies, copy session cookie values")
    lines.append(f"4. Save A: `python3 engine/engine/authn.py set --slug {slug} --ident A "
                 "--cookie 'name=value; name2=value2'`")
    lines.append(f"5. Save B: `python3 engine/engine/authn.py set --slug {slug} --ident B "
                 "--cookie 'name=value; name2=value2'`")
    lines.append(f"6. Verify: `python3 engine/engine/authn.py show --slug {slug}`")
    if plan["has_org_structure"]:
        lines.append("7. Create organization with user_a, invite user_b as viewer/member")
        lines.append("8. Note org_id for cross-org testing")

    return "\n".join(lines)


def bootstrap(program, base=DEFAULT_BASE):
    """Run the full bootstrap: analyze surface → plan → provision."""
    import state as S
    eng = S.Engagement(base, program)
    surface = eng.state.get("surface", [])

    if not surface:
        return {"error": "No surface discovered yet — run discovery first"}

    plan = analyze_auth_needs(surface)
    plan["slug"] = program

    # Save the plan
    plan_path = os.path.join(eng.dir, "auth-plan.md")
    with open(plan_path, "w") as f:
        f.write(format_plan(plan))

    # Check if sessions already exist
    import authsession as AS
    existing = AS.load(program, base)
    if AS.valid(existing):
        plan["session_status"] = "active"
        plan["session_user"] = existing.get("user", "unknown")
    else:
        plan["session_status"] = "none"

    plan["plan_path"] = plan_path
    return plan


def manual_inject(program, cookie=None, headers=None, token=None, host=None,
                   ident="A", base=DEFAULT_BASE):
    """Accept raw browser credentials and store them for the hunt.

    Use when automated signup fails (Cloudflare, CAPTCHA, SSO) and the operator
    pastes cookies/tokens from DevTools. Routes through authsession.set_manual
    which handles scope validation, host derivation, and authn mirroring.
    """
    import authsession as AS

    if not any([cookie, headers, token]):
        return {"error": "provide at least one of: cookie, headers, token"}

    result = AS.set_manual(
        program, host=host, cookie=cookie, headers=headers,
        token=token, ident=ident, base=base,
    )

    if result.get("error"):
        return result

    status = {
        "ok": True,
        "program": program,
        "ident": ident,
        "host": result.get("host", ""),
        "cookies": result.get("cookies", 0),
        "headers": result.get("headers", []),
        "next_steps": [],
    }

    if ident == "A":
        status["next_steps"].append(
            f"Session A stored. Inject B: manual_inject('{program}', cookie=..., ident='B')"
        )
    else:
        status["next_steps"].append("Both sessions stored — ready for cross-account hunt.")

    live = AS.check_live(program, base=base)
    if isinstance(live, dict) and live.get("error"):
        status["warning"] = f"Session may be expired: {live['error']}"
        status["next_steps"].append("Re-paste fresh cookies if the session is stale.")

    return status


def _selftest():
    mock_surface = [
        {"url": "https://api.acme.com/api/users/123", "method": "PUT", "params": ["user_id", "name"],
         "auth_required": True},
        {"url": "https://api.acme.com/api/users", "method": "GET", "params": ["page"],
         "auth_required": True},
        {"url": "https://api.acme.com/login", "method": "POST", "params": ["email", "password"]},
        {"url": "https://api.acme.com/api/orgs/456/members", "method": "GET", "params": ["org_id"],
         "auth_required": True},
        {"url": "https://api.acme.com/admin/settings", "method": "POST", "params": ["config"],
         "auth_required": True},
        {"url": "https://api.acme.com/api/payment/charge", "method": "POST", "params": ["amount"],
         "auth_required": True},
        {"url": "https://api.acme.com/public/health", "method": "GET", "params": []},
    ]

    plan = analyze_auth_needs(mock_surface)

    assert plan["total_endpoints"] == 7
    assert plan["auth_walled_endpoints"] == 5
    assert plan["auth_coverage_pct"] > 50
    assert len(plan["accounts_needed"]) >= 2  # at least user_a and user_b
    assert any(a["role"] == "user_a" for a in plan["accounts_needed"])
    assert any(a["role"] == "user_b" for a in plan["accounts_needed"])
    assert plan["has_org_structure"]  # /orgs/ detected
    assert len(plan["accounts_needed"]) >= 4  # should include org roles
    assert plan["write_endpoints"] >= 3
    assert plan["auth_hosts"]  # should find login host

    text = format_plan(plan)
    assert "Authentication Bootstrap Plan" in text
    assert "user_a" in text
    assert "user_b" in text
    assert "org" in text.lower()

    # Empty surface
    empty_plan = analyze_auth_needs([])
    assert empty_plan["total_endpoints"] == 0
    assert empty_plan["accounts_needed"]  # still recommends basic accounts

    print("authbootstrap.py: selftest PASSED")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _selftest()
    elif len(sys.argv) > 1 and sys.argv[1] == "plan":
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("cmd")
        p.add_argument("--program", required=True)
        p.add_argument("--base", default=DEFAULT_BASE)
        a = p.parse_args()
        result = bootstrap(a.program, a.base)
        print(json.dumps(result, indent=2, default=str))
    elif len(sys.argv) > 1 and sys.argv[1] == "inject":
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("cmd")
        p.add_argument("--program", required=True)
        p.add_argument("--cookie", default=None)
        p.add_argument("--token", default=None)
        p.add_argument("--header", action="append", default=[])
        p.add_argument("--host", default=None)
        p.add_argument("--ident", default="A")
        p.add_argument("--base", default=DEFAULT_BASE)
        a = p.parse_args()
        hdrs = {}
        for h in (a.header or []):
            k, _, v = h.partition(":")
            if k:
                hdrs[k.strip()] = v.strip()
        result = manual_inject(a.program, cookie=a.cookie, headers=hdrs or None,
                               token=a.token, host=a.host, ident=a.ident, base=a.base)
        print(json.dumps(result, indent=2, default=str))
    else:
        _selftest()
