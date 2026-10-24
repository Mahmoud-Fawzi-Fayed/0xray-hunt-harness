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

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

# Common hidden/admin paths to probe
HIDDEN_PATHS = [
    "/admin", "/debug", "/graphql", "/graphiql", "/playground",
    "/api-docs", "/swagger", "/swagger-ui", "/openapi.json", "/openapi.yaml",
    "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
    "/wp-admin", "/wp-login.php", "/elmah.axd", "/trace.axd",
    "/server-status", "/server-info", "/_debug", "/__debug__",
    "/actuator", "/actuator/health", "/actuator/env",
    "/api/v1", "/api/v2", "/api/v3",
    "/console", "/dashboard", "/settings", "/account", "/profile",
    "/internal", "/metrics", "/health", "/status", "/info",
]

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
    """Classify page type based on content."""
    url_l = url.lower()
    if any(k in url_l for k in ("/login", "/signin", "/auth")):
        return "auth"
    if any(k in url_l for k in ("/register", "/signup", "/join")):
        return "registration"
    if any(k in url_l for k in ("/admin", "/manage", "/dashboard")):
        return "admin"
    if any(k in url_l for k in ("/settings", "/account", "/profile")):
        return "settings"
    if any(k in url_l for k in ("/api/", "/graphql")):
        return "api"
    if forms:
        return "interactive"
    return "content"


def _detect_workflows(pages):
    """Detect multi-step workflows from page transitions."""
    workflows = []
    auth_flow = [p for p in pages if p.get("type") in ("auth", "registration")]
    if auth_flow:
        steps = sorted(set(p["url"] for p in auth_flow))
        if steps:
            workflows.append({"name": "authentication", "steps": steps})

    settings_flow = [p for p in pages if p.get("type") == "settings"]
    if settings_flow:
        steps = sorted(set(p["url"] for p in settings_flow))
        workflows.append({"name": "account-management", "steps": steps})

    return workflows


def _find_hidden_features(all_urls, js_routes, scope_hosts):
    """Identify potentially hidden or undocumented features."""
    hidden = []
    known_paths = {u.split("?")[0].rstrip("/") for u in all_urls}

    for route in js_routes:
        route_clean = route.split("?")[0].rstrip("/")
        if route_clean and route_clean not in known_paths:
            hidden.append({"path": route, "evidence": "found in JS but not in navigation", "source": "js-route"})

    for path in HIDDEN_PATHS:
        if path not in known_paths:
            hidden.append({"path": path, "evidence": "common hidden path (not yet probed)", "source": "wordlist"})

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
                    "params": [i.get("name", "") for i in form["inputs"] if i.get("name")],
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

    # Extract routes from JS URLs in state
    for ju in (js_urls or []):
        if isinstance(ju, str):
            all_urls.add(ju)

    # Detect roles from all content
    for cap in browser_caps:
        for k, v in cap.items():
            if isinstance(v, str):
                all_roles.update(_extract_roles(v))
                all_features.update(_extract_feature_flags(v))

    # Detect hidden features
    hidden = _find_hidden_features(all_urls, js_routes, scope_hosts)

    # Detect workflows
    workflows = _detect_workflows(pages)

    # Build unique API surface (deduplicated)
    api_seen = set()
    api_surface = []
    for ep in all_api_endpoints:
        key = (ep.get("method", "GET"), ep.get("path", ""))
        if key not in api_seen and key[1]:
            api_seen.add(key)
            api_surface.append(ep)

    roles = sorted(all_roles) if all_roles else ["anonymous", "authenticated"]

    return {
        "pages": pages,
        "workflows": workflows,
        "roles": roles,
        "hidden_features": hidden,
        "api_surface": api_surface,
        "feature_flags": sorted(all_features),
        "stats": {
            "pages_discovered": len(pages),
            "api_endpoints": len(api_surface),
            "forms": len(all_forms),
            "hidden_paths": len(hidden),
            "workflows": len(workflows),
            "roles": len(roles),
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
    assert any(p["type"] == "auth" for p in result["pages"]), [p["type"] for p in result["pages"]]
    assert any(p["type"] == "settings" for p in result["pages"]), [p["type"] for p in result["pages"]]
    assert any(ep["path"] == "/api/v1/users/me" for ep in result["api_surface"]), result["api_surface"]
    assert any(ep["path"] == "/api/account/delete" for ep in result["api_surface"]), result["api_surface"]
    assert result["hidden_features"], "should find hidden paths"
    assert result["workflows"], "should detect auth workflow"

    # Test empty state doesn't crash
    empty = analyze({})
    assert empty["stats"]["pages_discovered"] == 0

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
