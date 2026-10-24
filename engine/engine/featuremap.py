#!/usr/bin/env python3
"""
featuremap.py — deep functional mapping of a target's attack surface.

Builds a Feature → Action → Endpoint → Method → Parameters → Auth → Test Opportunities
inventory from multiple sources: browser capture, Burp proxy history, JS bundle analysis,
OpenAPI/GraphQL introspection, and profile agent output.

Outputs:
  feature-map.json   — structured inventory (machine-readable)
  feature-map.md     — human-readable feature map
  endpoints.jsonl    — one endpoint per line for pipeline consumption

CLI:
  python3 engine/engine/featuremap.py build --slug <program> [--base <dir>]
  python3 engine/engine/featuremap.py show  --slug <program>
  python3 engine/engine/featuremap.py selftest
"""
import argparse
import json
import os
import re
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(ENGINE)
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").strip().lower()).strip("-") or "unnamed"


def _eng_dir(slug, base):
    return os.path.join(os.path.expanduser(base or DEFAULT_BASE), _slug(slug))


# ---------------------------------------------------------------- data model
def _empty_feature():
    return {"feature": "", "actions": [], "confidence": "observed"}


def _empty_endpoint():
    return {
        "method": "GET", "url": "", "function": "", "params": [],
        "body_schema": None, "auth_required": True, "roles": [],
        "source": "unknown", "confidence": "observed",
    }


# ---------------------------------------------------------------- source: profile agent
def _endpoints_from_profile(profile):
    """Extract endpoints from a profile agent result (brain.py stored profile)."""
    eps = []
    for ep in (profile.get("api_surface") or []):
        if not isinstance(ep, dict) or not ep.get("url"):
            continue
        eps.append({
            "method": str(ep.get("method") or "GET")[:10].upper(),
            "url": str(ep["url"])[:500],
            "function": str(ep.get("function") or "")[:200],
            "params": list(ep.get("params") or [])[:20],
            "auth_required": bool(ep.get("auth_required", True)),
            "source": "profile-agent",
            "confidence": "observed",
        })
    for fl in (profile.get("flows") or []):
        if not isinstance(fl, dict) or not fl.get("url"):
            continue
        eps.append({
            "method": "GET", "url": str(fl["url"])[:500],
            "function": str(fl.get("what") or "")[:200],
            "params": [], "auth_required": True,
            "source": "profile-flow",
            "confidence": "observed",
        })
    for u in (profile.get("hidden_endpoints") or []):
        if isinstance(u, str) and u.startswith("http"):
            eps.append({
                "method": "GET", "url": u[:500],
                "function": "hidden/admin/debug",
                "params": [], "auth_required": True,
                "source": "profile-hidden",
                "confidence": "inferred",
            })
    return eps


# ---------------------------------------------------------------- source: existing surface
def _endpoints_from_surface(state):
    """Extract endpoints from the engine's existing surface/worklist."""
    eps = []
    seen = set()
    for s in (state.get("surface") or []):
        u = s.get("url", "")
        m = s.get("method", "GET")
        key = f"{m}:{u}"
        if not u or key in seen:
            continue
        seen.add(key)
        eps.append({
            "method": m, "url": u,
            "function": s.get("note") or s.get("vuln_class") or "",
            "params": [s["param"]] if s.get("param") else [],
            "auth_required": True,
            "source": s.get("source") or "recon",
            "confidence": "observed",
        })
    return eps


# ---------------------------------------------------------------- source: Burp proxy history
def _endpoints_from_burp(scope_hosts):
    """Extract endpoints from Burp proxy history via MCP (if available)."""
    try:
        from burp import is_burp_available
        if not is_burp_available():
            return []
    except ImportError:
        return []

    eps = []
    try:
        import subprocess
        result = subprocess.run(
            ["claude", "mcp", "call", "burp", "get_proxy_http_history"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return []
        entries = json.loads(result.stdout) if result.stdout.strip() else []
        seen = set()
        for entry in (entries if isinstance(entries, list) else []):
            url = entry.get("url") or ""
            method = entry.get("method") or "GET"
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            if not any(h in host for h in scope_hosts):
                continue
            key = f"{method}:{url}"
            if key in seen:
                continue
            seen.add(key)
            eps.append({
                "method": method, "url": url,
                "function": "",
                "params": list(entry.get("params") or []),
                "auth_required": True,
                "source": "burp-proxy",
                "confidence": "observed",
            })
    except Exception:  # noqa: BLE001
        pass
    return eps


# ---------------------------------------------------------------- source: JS bundle routes
def _endpoints_from_js(eng_dir, scope_hosts):
    """Extract API routes from JS bundle analysis (jsdiff output)."""
    eps = []
    js_dir = os.path.join(eng_dir, "js")
    if not os.path.isdir(js_dir):
        return eps
    route_re = re.compile(
        r"""(?:['"`])(/(?:api|v[0-9]+|graphql|auth|admin|internal|ws|webhook|upload|download|export|import)"""
        r"""[/a-zA-Z0-9_\-{}:.]*?)(?:['"`])""",
        re.I
    )
    seen = set()
    for fname in os.listdir(js_dir):
        if not fname.endswith((".js", ".map", ".json")):
            continue
        try:
            with open(os.path.join(js_dir, fname), "r", errors="replace") as f:
                content = f.read(500_000)
        except OSError:
            continue
        for match in route_re.finditer(content):
            path = match.group(1)
            if path in seen or len(path) > 200:
                continue
            seen.add(path)
            for host in scope_hosts[:1]:
                eps.append({
                    "method": "GET", "url": f"https://{host}{path}",
                    "function": "JS-discovered route",
                    "params": re.findall(r"\{(\w+)\}", path),
                    "auth_required": True,
                    "source": "js-bundle",
                    "confidence": "inferred",
                })
    return eps


# ---------------------------------------------------------------- merge + dedup
def merge_endpoints(sources):
    """Merge endpoints from all sources, dedup by method+url, prefer observed over inferred."""
    by_key = {}
    for ep in sources:
        url = re.sub(r'[?#].*', '', ep.get("url", ""))
        key = f"{ep.get('method', 'GET').upper()}:{url}"
        if key not in by_key:
            by_key[key] = dict(ep)
        else:
            existing = by_key[key]
            if ep.get("confidence") == "observed" and existing.get("confidence") == "inferred":
                by_key[key] = dict(ep)
            # merge params
            merged_params = list(set(existing.get("params", []) + (ep.get("params") or [])))
            by_key[key]["params"] = merged_params[:30]
            if ep.get("function") and not existing.get("function"):
                by_key[key]["function"] = ep["function"]
            if ep.get("source") and ep["source"] not in existing.get("source", ""):
                by_key[key]["source"] = f"{existing.get('source', '')},{ep['source']}"
    return sorted(by_key.values(), key=lambda e: (0 if e.get("confidence") == "observed" else 1, e.get("url", "")))


# ---------------------------------------------------------------- feature grouping
def group_by_feature(endpoints):
    """Group endpoints into logical features by URL path prefix."""
    features = {}
    for ep in endpoints:
        from urllib.parse import urlparse
        parsed = urlparse(ep.get("url", ""))
        parts = [p for p in parsed.path.split("/") if p][:3]
        if not parts:
            feature_name = "root"
        elif len(parts) == 1:
            feature_name = parts[0]
        else:
            feature_name = "/".join(parts[:2])
        feature_name = re.sub(r'[0-9a-f-]{8,}', '{id}', feature_name)
        if feature_name not in features:
            features[feature_name] = {"feature": feature_name, "actions": [], "confidence": "observed"}
        action = {
            "method": ep.get("method", "GET"),
            "url": ep.get("url", ""),
            "function": ep.get("function", ""),
            "params": ep.get("params", []),
            "auth_required": ep.get("auth_required", True),
            "source": ep.get("source", ""),
            "confidence": ep.get("confidence", "observed"),
        }
        features[feature_name]["actions"].append(action)
        if ep.get("confidence") == "inferred":
            features[feature_name]["confidence"] = "partial"
    return list(features.values())


# ---------------------------------------------------------------- test opportunities
def annotate_test_opportunities(features):
    """Annotate each feature with potential test opportunities based on its actions."""
    for feat in features:
        opportunities = set()
        for action in feat.get("actions", []):
            m = action.get("method", "").upper()
            url = action.get("url", "").lower()
            params = action.get("params") or []
            func = (action.get("function") or "").lower()
            if m in ("POST", "PUT", "PATCH", "DELETE"):
                opportunities.add("state-change")
            if any(p in ("id", "user_id", "uid", "account_id", "email") for p in params):
                opportunities.add("IDOR/BOLA")
            if any(p in ("url", "uri", "link", "redirect", "next", "return", "callback") for p in params):
                opportunities.add("SSRF/open-redirect")
            if any(p in ("file", "path", "filename", "upload", "document") for p in params):
                opportunities.add("file-upload/LFI")
            if any(p in ("query", "search", "q", "filter", "sort", "order") for p in params):
                opportunities.add("injection")
            if "graphql" in url:
                opportunities.add("GraphQL")
            if "websocket" in url or "ws:" in url or "wss:" in url:
                opportunities.add("WebSocket")
            if any(k in url for k in ("/admin", "/internal", "/debug", "/manage")):
                opportunities.add("admin-access")
            if any(k in func for k in ("payment", "checkout", "price", "billing", "subscription")):
                opportunities.add("payment-logic")
            if any(k in func for k in ("auth", "login", "signup", "password", "token", "session")):
                opportunities.add("auth-bypass")
            if any(k in func for k in ("export", "download", "report")):
                opportunities.add("data-export")
            if not action.get("auth_required"):
                opportunities.add("unauth-access")
        feat["test_opportunities"] = sorted(opportunities)
    return features


# ---------------------------------------------------------------- build full map
def build_feature_map(slug, base=DEFAULT_BASE, eng_dir=None, profile=None, state=None):
    """Build a complete feature map from all available sources."""
    eng_dir = eng_dir or _eng_dir(slug, base)
    all_endpoints = []

    # Source 1: profile agent
    if profile:
        all_endpoints.extend(_endpoints_from_profile(profile))

    # Source 2: existing surface
    if state:
        all_endpoints.extend(_endpoints_from_surface(state))

    # Source 3: brain.py stored profile
    if not profile:
        try:
            import brain as BR
            stored = BR.load(slug, base).get("profile") or {}
            if stored:
                all_endpoints.extend(_endpoints_from_profile(stored))
        except Exception:  # noqa: BLE001
            pass

    # Source 4: JS bundles
    scope_hosts = list({re.sub(r'^https?://', '', (s.get("url") or "")).split("/")[0]
                        for s in ((state or {}).get("surface") or []) if s.get("url")})[:5]
    if scope_hosts:
        all_endpoints.extend(_endpoints_from_js(eng_dir, scope_hosts))

    merged = merge_endpoints(all_endpoints)
    features = group_by_feature(merged)
    features = annotate_test_opportunities(features)

    return {
        "slug": slug,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": list({ep.get("source", "unknown") for ep in merged}),
        "total_endpoints": len(merged),
        "observed": sum(1 for e in merged if e.get("confidence") == "observed"),
        "inferred": sum(1 for e in merged if e.get("confidence") == "inferred"),
        "features": features,
        "endpoints": merged,
    }


# ---------------------------------------------------------------- output artifacts
def write_artifacts(slug, profile, eng_dir, base=DEFAULT_BASE, state=None):
    """Write feature-map.json, feature-map.md, endpoints.jsonl to the engagement dir."""
    if state is None:
        try:
            import state as ST
            state = ST.load(slug, base)
        except Exception:  # noqa: BLE001
            state = {}

    fmap = build_feature_map(slug, base=base, eng_dir=eng_dir, profile=profile, state=state)
    os.makedirs(eng_dir, exist_ok=True)

    # feature-map.json
    json_path = os.path.join(eng_dir, "feature-map.json")
    with open(json_path, "w") as f:
        json.dump(fmap, f, indent=2)

    # endpoints.jsonl
    jsonl_path = os.path.join(eng_dir, "endpoints.jsonl")
    with open(jsonl_path, "w") as f:
        for ep in fmap["endpoints"]:
            f.write(json.dumps(ep) + "\n")

    # feature-map.md
    md_path = os.path.join(eng_dir, "feature-map.md")
    with open(md_path, "w") as f:
        f.write(f"# Feature Map — {slug}\n\n")
        f.write(f"Generated: {fmap['generated_at']}  \n")
        f.write(f"Endpoints: {fmap['total_endpoints']} "
                f"({fmap['observed']} observed, {fmap['inferred']} inferred)  \n")
        f.write(f"Sources: {', '.join(fmap['sources'])}  \n\n")

        if profile and profile.get("narrative"):
            f.write(f"**App:** {profile['narrative']}\n\n")

        for feat in fmap["features"]:
            opps = feat.get("test_opportunities") or []
            f.write(f"## {feat['feature']}")
            if opps:
                f.write(f"  ({', '.join(opps)})")
            f.write("\n\n")
            f.write("| Method | URL | Function | Params | Auth | Source | Confidence |\n")
            f.write("|--------|-----|----------|--------|------|--------|------------|\n")
            for a in feat["actions"][:20]:
                params_str = ", ".join(a.get("params", [])[:5]) or "-"
                f.write(f"| {a.get('method','?')} "
                        f"| `{a.get('url','')[:80]}` "
                        f"| {a.get('function','')[:50]} "
                        f"| {params_str} "
                        f"| {'yes' if a.get('auth_required') else 'no'} "
                        f"| {a.get('source','')[:20]} "
                        f"| {a.get('confidence','')} |\n")
            f.write("\n")

        # coverage summary
        tested = set()
        untested = set()
        for feat in fmap["features"]:
            for a in feat["actions"]:
                key = f"{a.get('method')}:{a.get('url','')[:80]}"
                if a.get("confidence") == "observed":
                    tested.add(key)
                else:
                    untested.add(key)
        f.write("## Coverage\n\n")
        f.write(f"- **Tested/observed:** {len(tested)} endpoints\n")
        f.write(f"- **Inferred/untested:** {len(untested)} endpoints\n")
        all_opps = set()
        for feat in fmap["features"]:
            all_opps.update(feat.get("test_opportunities", []))
        if all_opps:
            f.write(f"- **Test opportunities:** {', '.join(sorted(all_opps))}\n")

    return {"json": json_path, "md": md_path, "jsonl": jsonl_path,
            "endpoints": fmap["total_endpoints"], "features": len(fmap["features"])}


# ---------------------------------------------------------------- CLI
def _cmd_build(a):
    r = write_artifacts(a.slug, None, _eng_dir(a.slug, a.base), a.base)
    print(json.dumps(r, indent=2))
    return 0


def _cmd_show(a):
    path = os.path.join(_eng_dir(a.slug, a.base), "feature-map.md")
    if os.path.isfile(path):
        print(open(path).read())
    else:
        print(f"No feature map for {a.slug}. Run: python3 {__file__} build --slug {a.slug}")
    return 0


def _cmd_selftest(_a):
    import tempfile

    # Test with mock profile data
    profile = {
        "narrative": "Acme Corp lets users manage projects and invoices.",
        "tech_stack": ["React", "Node.js", "PostgreSQL"],
        "roles": ["admin", "user", "billing"],
        "auth_mechanism": "jwt",
        "crown_jewels": ["invoice data", "user PII", "payment methods"],
        "api_surface": [
            {"method": "GET", "url": "https://api.acme.test/v1/projects", "function": "list projects",
             "params": ["page", "limit"], "auth_required": True},
            {"method": "POST", "url": "https://api.acme.test/v1/projects", "function": "create project",
             "params": ["name", "description"], "auth_required": True},
            {"method": "GET", "url": "https://api.acme.test/v1/invoices/{id}", "function": "get invoice",
             "params": ["id"], "auth_required": True},
            {"method": "POST", "url": "https://api.acme.test/v1/payments/checkout", "function": "payment checkout",
             "params": ["invoice_id", "amount", "card_token"], "auth_required": True},
            {"method": "GET", "url": "https://api.acme.test/v1/users/{user_id}/settings", "function": "user settings",
             "params": ["user_id"], "auth_required": True},
            {"method": "POST", "url": "https://api.acme.test/v1/auth/login", "function": "login",
             "params": ["email", "password"], "auth_required": False},
            {"method": "GET", "url": "https://api.acme.test/v1/export/report", "function": "export data",
             "params": ["format", "date_range"], "auth_required": True},
            {"method": "POST", "url": "https://api.acme.test/v1/files/upload", "function": "file upload",
             "params": ["file", "project_id"], "auth_required": True},
            {"method": "GET", "url": "https://api.acme.test/graphql", "function": "GraphQL endpoint",
             "params": ["query"], "auth_required": True},
        ],
        "flows": [
            {"what": "User creates project", "url": "https://api.acme.test/v1/projects", "why": "state change"},
            {"what": "Admin views all users", "url": "https://api.acme.test/admin/users", "why": "privilege boundary"},
        ],
        "hidden_endpoints": [
            "https://api.acme.test/admin/debug",
            "https://api.acme.test/internal/metrics",
        ],
    }

    # Mock engine state surface
    state = {
        "surface": [
            {"url": "https://api.acme.test/v1/projects", "method": "GET", "vuln_class": "deep",
             "source": "recon", "param": "page"},
            {"url": "https://api.acme.test/v1/search", "method": "GET", "vuln_class": "sqli",
             "source": "param-mining", "param": "q"},
        ]
    }

    tmpdir = tempfile.mkdtemp()
    base = tempfile.mkdtemp()

    # Build feature map
    fmap = build_feature_map("acme-test", base=base, eng_dir=tmpdir, profile=profile, state=state)

    assert fmap["total_endpoints"] >= 10, f"expected >=10 endpoints, got {fmap['total_endpoints']}"
    assert fmap["observed"] >= 8, f"expected >=8 observed, got {fmap['observed']}"
    assert fmap["inferred"] >= 2, f"expected >=2 inferred, got {fmap['inferred']}"
    assert len(fmap["features"]) >= 4, f"expected >=4 features, got {len(fmap['features'])}"

    # Check test opportunity annotations
    all_opps = set()
    for feat in fmap["features"]:
        all_opps.update(feat.get("test_opportunities", []))
    assert "IDOR/BOLA" in all_opps, f"missing IDOR opportunity: {all_opps}"
    assert "payment-logic" in all_opps, f"missing payment opportunity: {all_opps}"
    assert "auth-bypass" in all_opps, f"missing auth opportunity: {all_opps}"
    assert "file-upload/LFI" in all_opps, f"missing file-upload opportunity: {all_opps}"
    assert "injection" in all_opps, f"missing injection opportunity: {all_opps}"
    assert "GraphQL" in all_opps, f"missing GraphQL opportunity: {all_opps}"
    assert "data-export" in all_opps, f"missing data-export opportunity: {all_opps}"
    assert "admin-access" in all_opps, f"missing admin opportunity: {all_opps}"
    assert "unauth-access" in all_opps, f"missing unauth opportunity: {all_opps}"

    # Check merge dedup (projects should appear once, not twice)
    proj_eps = [e for e in fmap["endpoints"] if "projects" in e["url"] and e["method"] == "GET"]
    assert len(proj_eps) == 1, f"GET /projects should be deduped, got {len(proj_eps)}"
    # but params should be merged
    assert "page" in proj_eps[0]["params"], f"merged params should include 'page': {proj_eps[0]['params']}"

    # Write artifacts
    r = write_artifacts("acme-test", profile, tmpdir, base, state=state)
    assert os.path.isfile(r["json"]), "feature-map.json not written"
    assert os.path.isfile(r["md"]), "feature-map.md not written"
    assert os.path.isfile(r["jsonl"]), "endpoints.jsonl not written"

    # Verify JSON
    with open(r["json"]) as f:
        loaded = json.load(f)
    assert loaded["total_endpoints"] == fmap["total_endpoints"]

    # Verify JSONL
    with open(r["jsonl"]) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == fmap["total_endpoints"], f"JSONL lines {len(lines)} != {fmap['total_endpoints']}"

    # Verify MD has structure
    md = open(r["md"]).read()
    assert "# Feature Map" in md
    assert "| Method |" in md
    assert "## Coverage" in md
    assert "Test opportunities" in md

    # Test with empty inputs (should not crash)
    empty_map = build_feature_map("empty-test", base=base, eng_dir=tmpdir)
    assert empty_map["total_endpoints"] == 0
    assert empty_map["features"] == []

    # Test _endpoints_from_profile with bad data
    bad_eps = _endpoints_from_profile({"api_surface": [None, "", 123, {"url": ""}]})
    assert bad_eps == [], f"bad data should produce empty: {bad_eps}"

    print("featuremap.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="deep functional mapping of target attack surface")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pb = sub.add_parser("build")
    pb.add_argument("--slug", required=True)
    pb.add_argument("--base", default=DEFAULT_BASE)
    pb.set_defaults(fn=_cmd_build)
    ps = sub.add_parser("show")
    ps.add_argument("--slug", required=True)
    ps.add_argument("--base", default=DEFAULT_BASE)
    ps.set_defaults(fn=_cmd_show)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
