#!/usr/bin/env python3
"""
explorer.py — systematic functional discovery from captured browser data and JS analysis.

Builds an app model from browser captures, JS bundles, and HTML content without
requiring Burp. Discovers hidden functionality, workflows, roles, and API surface.

CLI:
  python3 engine/engine/explorer.py analyze --state <state.json>
  python3 engine/engine/explorer.py selftest
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

_ATTR_URL_RE = re.compile(
    r'''(?:href|src|action|data-url|data-api|data-endpoint|data-href|formaction)'''
    r'''=["']([^"'#][^"']*?)["']''', re.I)
_ONCLICK_URL_RE = re.compile(
    r'''(?:window\.location|location\.href|navigate|redirect)\s*[=(]\s*["']([^"']+)["']''', re.I)
_JS_API_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete)|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]''', re.I)
_ROUTE_DEF_RE = re.compile(
    r'''(?:path|route|url)\s*[:=]\s*["'`](/[a-zA-Z0-9/:_\-\[\].{}]+)["'`]''', re.I)
_FEATURE_FLAG_RE = re.compile(
    r'''(?:feature[_-]?flag|toggle|experiment|variant)\s*[:=]\s*["']([^"']+)["']''', re.I)
_ROLE_RE = re.compile(
    r'''(?:role|permission|access[_-]?level|user[_-]?type)\s*[:=]\s*["']([^"']+)["']''', re.I)


def _extract_urls_from_html(html, base_host=""):
    """Extract all URLs from HTML attributes and inline JS."""
    urls = set()
    for m in _ATTR_URL_RE.finditer(html):
        urls.add(m.group(1))
    for m in _ONCLICK_URL_RE.finditer(html):
        urls.add(m.group(1))
    for m in _JS_API_RE.finditer(html):
        urls.add(m.group(1))
    return urls


def _extract_routes_from_js(js_content):
    """Extract route definitions from JS source."""
    routes = set()
    for m in _ROUTE_DEF_RE.finditer(js_content):
        routes.add(m.group(1))
    return routes


def _extract_feature_flags(content):
    """Find feature flags/toggles in source."""
    return list({m.group(1) for m in _FEATURE_FLAG_RE.finditer(content)})


def _extract_roles(content):
    """Find role/permission references in source."""
    return list({m.group(1) for m in _ROLE_RE.finditer(content)})


def _classify_page(url, links, forms):
    """Describe observed interaction shape without naming a product convention."""
    return "interactive" if forms else "observed"


def _detect_workflows(pages, forms=None):
    """Group observed interactions into workflows without inferring a named business flow."""
    if forms is None:
        forms = [form for page in pages for form in page.get("forms", [])]
    steps = sorted({form.get("url") for form in forms if form.get("url")})
    return [{"name": "observed-interaction-sequence", "steps": steps}] if steps else []


def _find_hidden_features(all_urls, js_routes, scope_hosts):
    """Identify potentially hidden or undocumented features."""
    hidden = []
    known_paths = {u.split("?")[0].rstrip("/") for u in all_urls}

    for route in js_routes:
        route_clean = route.split("?")[0].rstrip("/")
        if route_clean and route_clean not in known_paths:
            hidden.append({"path": route, "evidence": "found in JS but not in navigation", "source": "js-route"})

    return hidden[:50]


def analyze(state, scope=None):
    """Build app model from browser captures and state data.

    Returns:
        dict with pages, workflows, roles, hidden_features, api_surface, stats
    """
    browser_caps = state.get("browser_capture", [])
    novel_hosts = state.get("novel_hosts", [])
    js_urls = state.get("js_urls", [])
    surface = state.get("surface", [])

    pages = []
    all_urls = set()
    all_api_endpoints = []
    all_forms = []
    all_roles = set()
    all_features = set()
    js_routes = set()

    scope_hosts = []
    if scope:
        scope_hosts = scope.get("in_scope", []) if isinstance(scope, dict) else getattr(scope, "in_scope", [])

    # Process browser captures (forms, buttons, XHR)
    for cap in browser_caps:
        source = cap.get("source", "")
        url = cap.get("url", cap.get("action", ""))

        if source == "form":
            form = {
                "url": cap.get("action", ""),
                "method": (cap.get("method") or "GET").upper(),
                "inputs": cap.get("inputs", []),
                "source": "form",
            }
            all_forms.append(form)
            if form["url"]:
                all_api_endpoints.append({
                    "method": form["method"],
                    "path": form["url"],
                    "params": [i if isinstance(i, str) else i.get("name", "") for i in form.get("inputs", []) if (i if isinstance(i, str) else i.get("name"))],
                    "source": "form-action",
                })

        elif source == "button":
            if cap.get("formaction"):
                all_api_endpoints.append({
                    "method": (cap.get("formmethod") or "POST").upper(),
                    "path": cap["formaction"],
                    "params": [],
                    "source": "button-action",
                })

        elif source in ("fetch", "xhr"):
            all_api_endpoints.append({
                "method": (cap.get("method") or "GET").upper(),
                "path": cap.get("url", ""),
                "params": [],
                "source": "js-api-call",
                "status": cap.get("status"),
            })

        if url:
            all_urls.add(url)

    # Process surface items for page model
    seen_pages = set()
    for item in surface:
        url = item.get("url", "")
        if not url or url in seen_pages:
            continue
        seen_pages.add(url)
        page_forms = [f for f in all_forms if f.get("url", "").startswith(url.split("?")[0])]
        page_type = _classify_page(url, [], page_forms)
        pages.append({
            "url": url,
            "method": item.get("method", "GET"),
            "type": page_type,
            "params": item.get("params", []) if isinstance(item.get("params"), list)
                      else [item["params"]] if item.get("params") else [],
            "forms": page_forms,
            "confidence": item.get("confidence", "observed"),
        })
        all_urls.add(url)

    # Extract operations and routes only from supplied source evidence.
    for cap in browser_caps:
        all_urls.update(_extract_urls_from_html(str(cap.get("content") or cap.get("html") or "")))
        js_routes.update(_extract_routes_from_js(str(cap.get("js_content") or cap.get("content") or "")))
    for ju in (js_urls or []):
        if isinstance(ju, str):
            all_urls.add(ju)
        elif isinstance(ju, dict):
            if ju.get("url"):
                all_urls.add(ju["url"])
            content = str(ju.get("js_content") or ju.get("content") or "")
            all_urls.update(_extract_urls_from_html(content))
            js_routes.update(_extract_routes_from_js(content))

    # Detect roles from all content
    for cap in browser_caps:
        for k, v in cap.items():
            if isinstance(v, str):
                all_roles.update(_extract_roles(v))
                all_features.update(_extract_feature_flags(v))

    # Detect hidden features
    hidden = _find_hidden_features(all_urls, js_routes, scope_hosts)

    # Detect workflows
    workflows = _detect_workflows(pages, all_forms)

    # Build unique API surface (deduplicated)
    api_seen = set()
    api_surface = []
    for ep in all_api_endpoints:
        key = (ep.get("method", "GET"), ep.get("path", ""))
        if key not in api_seen and key[1]:
            api_seen.add(key)
            api_surface.append(ep)

    roles = sorted(all_roles) if all_roles else ["anonymous", "authenticated"]

    # Build structured inventory
    burp_eps = [ep for ep in all_api_endpoints if ep.get("source") not in ("form-action", "button-action", "js-api-call")]
    browser_only = [ep for ep in all_api_endpoints if ep.get("source") in ("form-action", "button-action", "js-api-call")]
    inventory = build_inventory(
        browser_caps, burp_eps, list(js_routes),
        state, role=state.get("current_role"),
    )

    return {
        "pages": pages,
        "workflows": workflows,
        "roles": roles,
        "hidden_features": hidden,
        "api_surface": api_surface,
        "feature_flags": sorted(all_features),
        "inventory": inventory,
        "stats": {
            "pages_discovered": len(pages),
            "api_endpoints": len(api_surface),
            "forms": len(all_forms),
            "hidden_paths": len(hidden),
            "workflows": len(workflows),
            "roles": len(roles),
            "inventory_features": inventory["stats"]["features"],
            "inventory_operations": inventory["stats"]["operations"],
        },
    }


_SESSION_PATTERNS = {
    "jwt": re.compile(r"bearer|authorization|jwt", re.I),
    "cookie": re.compile(r"set-cookie|session_?id|csrf", re.I),
    "bearer": re.compile(r"api[_-]?key|x-api-key", re.I),
}


def _path_prefix(url, depth=2):
    """Extract path prefix for feature grouping (first N segments)."""
    try:
        p = urlparse(url).path or "/"
    except Exception:
        p = "/"
    parts = [s for s in p.split("/") if s]
    return "/" + "/".join(parts[:depth]) if parts else "/"


def _detect_api_specs(all_urls, api_surface):
    """Return schemas actually present in captured content, not conventional paths."""
    specs = []
    for ep in api_surface:
        content = ep.get("content") or ep.get("body") or ep.get("schema") or {}
        text = json.dumps(content) if not isinstance(content, str) else content
        url = ep.get("url") or ep.get("path") or ""
        if '"openapi"' in text or '"swagger"' in text:
            specs.append({"path": url, "type": "openapi", "confidence": "observed"})
        elif '"__schema"' in text or '"queryType"' in text:
            specs.append({"path": url, "type": "graphql", "confidence": "observed"})
    return specs


def _detect_session_mechanism(browser_caps):
    """Infer session mechanism from captured data."""
    text = json.dumps(browser_caps)
    for mech, pat in _SESSION_PATTERNS.items():
        if pat.search(text):
            return mech
    return "unknown"


def build_inventory(browser_captures, burp_endpoints, js_routes, state, role=None):
    """Build a normalized application inventory model.

    Returns structured inventory: features → operations → workflows → auth model.
    """
    ops_by_prefix = {}
    op_id = 0

    def _add_op(url, method, params, source, confidence, auth_req=False, status=None, evidence=None, content=None):
        nonlocal op_id
        op_id += 1
        prefix = _path_prefix(url)
        op = {
            "id": op_id,
            "url": url,
            "method": (method or "GET").upper(),
            "params": params or [],
            "auth_required": auth_req,
            "source": source,
            "confidence": confidence,
            "roles_tested": [role] if role else [],
            "evidence": evidence,
            "content": content,
        }
        if status is not None:
            op["status"] = status
        ops_by_prefix.setdefault(prefix, []).append(op)
        return op

    # Browser captures
    for cap in (browser_captures or []):
        src = cap.get("source", "")
        if src == "form":
            raw_inputs = cap.get("inputs") or []
            params = [i if isinstance(i, str) else i.get("name", "") for i in raw_inputs
                      if (i if isinstance(i, str) else i.get("name"))]
            _add_op(cap.get("action", ""), cap.get("method", "POST"), params,
                     "form", "observed", evidence="browser_capture")
        elif src == "button" and cap.get("formaction"):
            _add_op(cap["formaction"], cap.get("formmethod", "POST"), [],
                     "button", "observed", evidence="browser_capture")
        elif src in ("fetch", "xhr"):
            _add_op(cap.get("url", ""), cap.get("method", "GET"), cap.get("params") or [],
                     "js-api", "observed", status=cap.get("status"), evidence="browser_capture",
                     content=cap.get("content") or cap.get("body") or cap.get("schema"))

    # Burp endpoints
    for ep in (burp_endpoints or []):
        url = ep.get("url") or ep.get("path", "")
        auth = ep.get("auth_required", False)
        status = ep.get("status")
        _add_op(url, ep.get("method", "GET"), ep.get("params", []),
                 "burp", "observed", auth_req=auth or (status in (401, 403)),
                 status=status, evidence="burp_history")

    # JS routes
    for route in (js_routes or []):
        r = route if isinstance(route, str) else route.get("path", "")
        if r:
            _add_op(r, "GET", [], "js-analysis", "inferred", evidence="js_discovery")

    # Build features from grouped operations
    features = []
    for prefix, ops in sorted(ops_by_prefix.items()):
        name_parts = [s for s in prefix.split("/") if s]
        name = "-".join(name_parts) if name_parts else "root"
        features.append({
            "name": name,
            "path_prefix": prefix,
            "operations": ops,
            "workflows": [],
        })

    all_operations = []
    for feat in features:
        all_operations.extend(feat["operations"])
        if len(feat["operations"]) > 1:
            feat["workflows"].append({
                "name": "observed-operation-sequence",
                "steps": [op["url"] for op in feat["operations"]],
            })
    api_specs = _detect_api_specs(set(), all_operations)

    login_eps = [op["url"] for op in all_operations
                 if any((p.get("type") == "password" if isinstance(p, dict) else str(p).lower() == "password")
                        for p in op.get("params", []))]
    roles_discovered = set()
    for feat in features:
        for op in feat["operations"]:
            roles_discovered.update(op.get("roles_tested", []))
    roles_discovered.discard(None)

    return {
        "features": features,
        "api_specs": api_specs,
        "auth_model": {
            "login_endpoints": sorted(set(login_eps)),
            "roles_discovered": sorted(roles_discovered) or ["anonymous"],
            "session_mechanism": _detect_session_mechanism(browser_captures or []),
        },
        "stats": {
            "features": len(features),
            "operations": op_id,
            "api_specs": len(api_specs),
        },
    }


def analyze_html(html, url=""):
    """Analyze a single HTML page for interactive elements and URLs."""
    urls = _extract_urls_from_html(html)
    roles = _extract_roles(html)
    features = _extract_feature_flags(html)
    routes = _extract_routes_from_js(html)
    return {
        "url": url,
        "urls_found": sorted(urls),
        "routes": sorted(routes),
        "roles": roles,
        "feature_flags": features,
    }


# ---------------------------------------------------------------- CLI

def _cmd_analyze(a):
    state_path = os.path.expanduser(a.state)
    if not os.path.isfile(state_path):
        print(f"State file not found: {state_path}", file=sys.stderr)
        return 1
    with open(state_path) as f:
        state = json.load(f)
    scope = None
    if a.scope:
        with open(os.path.expanduser(a.scope)) as f:
            scope = json.load(f)
    result = analyze(state, scope)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_selftest(_a):
    # Test HTML extraction
    html = '''
    <a href="/dashboard">Dashboard</a>
    <a href="/api/users/5">Profile</a>
    <form action="/api/login" method="POST">
      <input name="email" type="email">
      <input name="password" type="password">
    </form>
    <button formaction="/api/delete" formmethod="DELETE">Delete</button>
    <script>
      fetch("/api/v1/settings");
      const role = "admin";
      window.location = "/admin/panel";
      const featureFlag = "dark-mode";
      path: "/api/internal/debug"
    </script>
    '''
    result = analyze_html(html, url="https://example.com")
    assert "/dashboard" in result["urls_found"], result["urls_found"]
    assert "/api/login" in result["urls_found"], result["urls_found"]
    assert "/api/v1/settings" in result["urls_found"], result["urls_found"]
    assert "/admin/panel" in result["urls_found"], result["urls_found"]
    assert "/api/internal/debug" in result["routes"], result["routes"]
    assert "admin" in result["roles"], result["roles"]
    assert "dark-mode" in result["feature_flags"], result["feature_flags"]

    # Test analyze with mock state
    state = {
        "browser_capture": [
            {"source": "form", "action": "/api/register", "method": "POST",
             "inputs": [{"name": "email"}, {"name": "password"}]},
            {"source": "fetch", "url": "/api/v1/users/me", "method": "GET", "status": 200},
            {"source": "xhr", "url": "/api/v1/notifications", "method": "GET"},
            {"source": "script", "url": "/app.js", "content": "const route = {path: '/api/internal/debug'};"},
            {"source": "button", "formaction": "/api/account/delete", "formmethod": "DELETE"},
        ],
        "surface": [
            {"url": "https://example.com/login", "method": "GET"},
            {"url": "https://example.com/dashboard", "method": "GET"},
            {"url": "https://example.com/settings", "method": "GET"},
            {"url": "https://example.com/api/users/5", "method": "GET", "params": ["id"]},
        ],
    }
    result = analyze(state)
    assert result["stats"]["pages_discovered"] == 4, result["stats"]
    assert result["stats"]["api_endpoints"] >= 3, result["stats"]
    assert result["stats"]["forms"] == 1, result["stats"]
    assert all(p["type"] in ("observed", "interactive") for p in result["pages"])
    assert any(ep["path"] == "/api/v1/users/me" for ep in result["api_surface"]), result["api_surface"]
    assert any(ep["path"] == "/api/account/delete" for ep in result["api_surface"]), result["api_surface"]
    assert result["hidden_features"], "should find source-evidenced unlinked paths"
    assert result["workflows"], "should detect observed interaction workflows"

    # Test empty state doesn't crash
    empty = analyze({})
    assert empty["stats"]["pages_discovered"] == 0

    # Test build_inventory directly
    inv = build_inventory(
        browser_captures=[
            {"source": "form", "action": "/api/login", "method": "POST", "inputs": ["email", "password"]},
            {"source": "fetch", "url": "/api/v1/users/me", "method": "GET", "status": 200},
            {"source": "fetch", "url": "/graphql", "method": "POST",
             "content": {"data": {"__schema": {"queryType": {"name": "Query"}}}}},
        ],
        burp_endpoints=[
            {"url": "/api/v1/orders", "method": "GET", "params": ["page"], "status": 200},
            {"url": "/api/v1/orders", "method": "POST", "params": ["item_id", "qty"], "status": 401,
             "auth_required": True},
        ],
        js_routes=["/api/internal/debug", "/admin/settings"],
        state={},
        role="user_a",
    )
    assert inv["features"], "should have features"
    assert inv["stats"]["operations"] >= 5, inv["stats"]
    assert inv["api_specs"], f"should detect /graphql: {inv['api_specs']}"
    assert inv["auth_model"]["roles_discovered"] == ["user_a"], inv["auth_model"]
    # Auth model detects login endpoint
    assert any("login" in ep for ep in inv["auth_model"]["login_endpoints"]), inv["auth_model"]
    # Operations have role tracking
    ops = [op for f in inv["features"] for op in f["operations"]]
    assert all(op.get("roles_tested") == ["user_a"] for op in ops), "all ops should track role"

    # Verify analyze() includes inventory
    assert result.get("inventory"), "analyze should include inventory"
    assert result["inventory"]["features"], "inventory should have features"

    print("explorer.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="systematic functional discovery")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("analyze", help="Analyze captured state for app model")
    pa.add_argument("--state", required=True, help="Path to state.json")
    pa.add_argument("--scope", default=None, help="Path to scope.json")
    pa.set_defaults(fn=_cmd_analyze)

    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
