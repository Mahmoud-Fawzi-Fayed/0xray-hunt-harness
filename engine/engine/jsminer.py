#!/usr/bin/env python3
"""
jsminer.py — JS bundle discovery and mining for API endpoints, GraphQL operations,
auth patterns, route definitions, and security-relevant tokens.

Automates the manual JS analysis step in the discovery phase: fetches the target's
HTML, extracts script src URLs, downloads app bundles (skipping vendor/framework),
and runs regex-based extraction for attack surface intel.

CLI:
  python3 engine/engine/jsminer.py --url <seed_url>         # full discover+mine
  python3 engine/engine/jsminer.py --file <path.js>         # mine a local file
  python3 engine/engine/jsminer.py selftest
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse, urljoin

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

# --- Bundle filtering ---
# Skip known framework/vendor bundles that rarely contain app-specific routes.
_VENDOR_PATTERNS = re.compile(
    r"(react|vue|angular|polyfill|vendor|chunk-vendors|framework|runtime|webpack|"
    r"node_modules|lodash|jquery|moment|core-js|regenerator|babel|tslib)",
    re.I,
)

# --- Extraction patterns ---

_API_PATH = re.compile(
    r"""(?:"|'|`)(/api/[a-zA-Z0-9_/${}:.-]+)(?:"|'|`)"""
    r"""|(?:"|'|`)(https?://[a-zA-Z0-9._-]+/api/[a-zA-Z0-9_/${}:.-]+)(?:"|'|`)""",
)

_ROUTE_PATH = re.compile(
    r"""(?:path|route|url|to|href)\s*[:=]\s*(?:"|'|`)(/[a-z][a-zA-Z0-9_/${}:.*-]+)(?:"|'|`)""",
    re.I,
)

_GRAPHQL_OP = re.compile(
    r"""(?:mutation|query|subscription)\s+([A-Z][a-zA-Z0-9_]+)\s*[\({]""",
)

_GRAPHQL_TAG = re.compile(
    r"""gql\s*`([^`]{5,500})`""",
)

_AUTH_PATTERNS = [
    ("csrf_header", re.compile(r"""["']([Xx]-[Cc][Ss][Rr][Ff]-[Tt]oken)["']""")),
    ("csrf_cookie", re.compile(r"""["'](XSRF-TOKEN|csrf[_-]token)["']""", re.I)),
    ("bearer", re.compile(r"""[Aa]uthorization[^"']*["']Bearer\s""")),
    ("cookie_name", re.compile(r"""(?:cookie|Cookie)[^"']*["'](_[a-z_]+_session|_[a-z_]+)["']""")),
    ("session_header", re.compile(r"""["'](Authorization-Type|X-[A-Z][a-zA-Z]+-(?:Access-Token|Key|Secret)|X-Api-Key)["']""", re.I)),
]

# Detect any absolute URL embedded in JS — scope filtering happens downstream, not here.
_INTERESTING_URLS = re.compile(
    r"""(https?://[a-zA-Z0-9._-]{4,}(?:\.[a-zA-Z]{2,})+/[a-zA-Z0-9./_?&=-]{2,})""",
)

_HIDDEN_ENDPOINT = re.compile(
    r"""(?:"|'|`)((?:/(?:admin|internal|debug|staging|graphql|ws|cable|health|status|metrics)"""
    r"""(?:/[a-zA-Z0-9_{}$:.-]*)*))(?:"|'|`)""",
    re.I,
)

_TOKEN_PATTERN = re.compile(
    r"""(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]+\.[A-Za-z0-9_-]+)""",
)

_FETCH_CALL = re.compile(
    r"""(?:fetch|axios|\.(?:get|post|put|patch|delete))\s*\(\s*(?:"|'|`)([^"'`]+)(?:"|'|`)""",
    re.I,
)



def discover_bundles(url, scope=None):
    """Fetch HTML at *url*, extract <script src> URLs, filter out vendor/framework.

    *scope* — a Scope object (optional). When set, only bundle URLs on in-scope hosts
    are returned. Out-of-scope bundles are skipped entirely — no CDN exceptions.

    Returns list of absolute URLs to app-specific JS bundles.
    """
    import netget

    status, html, _hdrs = netget.get(url, headers={"Accept": "text/html"})
    if status == 0 or not html:
        return []

    src_re = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
    all_srcs = src_re.findall(html)

    bundles = []
    for src in all_srcs:
        abs_url = urljoin(url, src)
        parsed = urlparse(abs_url)
        basename = os.path.basename(parsed.path)
        if _VENDOR_PATTERNS.search(basename):
            continue
        if not basename.endswith(".js"):
            continue
        if scope and not scope.in_scope_host(abs_url):
            continue
        bundles.append(abs_url)
    return bundles


def mine_content(js_text):
    """Extract security-relevant intel from a JS string.

    Returns dict with keys: api_paths, graphql_ops, auth_patterns, routes,
    hidden_endpoints, interesting_urls, tokens, fetch_calls.
    """
    result = {
        "api_paths": [],
        "graphql_ops": [],
        "auth_patterns": [],
        "routes": [],
        "hidden_endpoints": [],
        "interesting_urls": [],
        "tokens": [],
        "fetch_calls": [],
    }

    for m in _API_PATH.finditer(js_text):
        path = m.group(1) or m.group(2)
        if path and path not in result["api_paths"]:
            result["api_paths"].append(path)

    for m in _GRAPHQL_OP.finditer(js_text):
        op = m.group(1)
        if op not in result["graphql_ops"]:
            result["graphql_ops"].append(op)

    for m in _GRAPHQL_TAG.finditer(js_text):
        body = m.group(1).strip()[:200]
        if body not in result["graphql_ops"]:
            result["graphql_ops"].append(body)

    for label, pat in _AUTH_PATTERNS:
        for m in pat.finditer(js_text):
            entry = f"{label}:{m.group(1) if m.lastindex else m.group(0)}"
            if entry not in result["auth_patterns"]:
                result["auth_patterns"].append(entry)

    for m in _ROUTE_PATH.finditer(js_text):
        route = m.group(1)
        if route not in result["routes"] and not route.startswith("/node_modules"):
            result["routes"].append(route)

    for m in _HIDDEN_ENDPOINT.finditer(js_text):
        ep = m.group(1)
        if ep not in result["hidden_endpoints"]:
            result["hidden_endpoints"].append(ep)

    for m in _INTERESTING_URLS.finditer(js_text):
        u = m.group(1)
        if u not in result["interesting_urls"]:
            result["interesting_urls"].append(u)

    for m in _TOKEN_PATTERN.finditer(js_text):
        tok = m.group(1)
        if tok not in result["tokens"]:
            result["tokens"].append(tok)

    for m in _FETCH_CALL.finditer(js_text):
        call = m.group(1)
        if call not in result["fetch_calls"] and not call.startswith("data:"):
            result["fetch_calls"].append(call)

    return result


def mine_bundle(url_or_path, scope=None):
    """Mine a single JS bundle (URL or local file path). Returns mine_content() dict.

    *scope* — a Scope object (optional). Out-of-scope URLs are refused.
    """
    if os.path.isfile(url_or_path):
        with open(url_or_path) as f:
            return mine_content(f.read())

    import netget
    if scope and not scope.in_scope_host(url_or_path):
        return mine_content("")
    status, text, _hdrs = netget.get(url_or_path)
    if status == 0 or not text:
        return mine_content("")
    return mine_content(text)


def mine_all(seed_url, scope=None):
    """Discover bundles at *seed_url*, mine each, return merged results.

    *scope* — a Scope object (optional). Passed through to discover_bundles and
    mine_bundle so the scope guard controls which hosts are contacted.

    Returns dict with keys matching mine_content() plus 'bundles_found'.
    """
    bundles = discover_bundles(seed_url, scope=scope)

    merged = {
        "seed_url": seed_url,
        "bundles_found": len(bundles),
        "bundle_urls": bundles,
        "api_paths": [],
        "graphql_ops": [],
        "auth_patterns": [],
        "routes": [],
        "hidden_endpoints": [],
        "interesting_urls": [],
        "tokens": [],
        "fetch_calls": [],
    }

    for burl in bundles:
        result = mine_bundle(burl, scope=scope)
        for key in ("api_paths", "graphql_ops", "auth_patterns", "routes",
                     "hidden_endpoints", "interesting_urls", "tokens", "fetch_calls"):
            for item in result.get(key, []):
                if item not in merged[key]:
                    merged[key].append(item)

    return merged


# --- CLI ---

def _main(argv):
    p = argparse.ArgumentParser(description="JS bundle miner for bug bounty recon")
    p.add_argument("--url", help="Seed URL to discover and mine bundles from")
    p.add_argument("--file", help="Local JS file to mine")
    args = p.parse_args(argv)

    if args.file:
        result = mine_bundle(args.file)
    elif args.url:
        result = mine_all(args.url)
    else:
        p.print_help()
        return 1

    print(json.dumps(result, indent=2))
    return 0


# --- Selftest ---

def _selftest():
    mock_js = r"""
    import {a} from "./users.js";
    const API_BASE = "/api/v2";
    fetch("/api/community/apply/${token}");
    axios.post("/api/users/me", data);
    const url = "https://api.collabs.shopify.com/merchant/graphql";

    const LOGIN_QUERY = gql`
      mutation LoginUser($email: String!, $password: String!) {
        login(email: $email, password: $password) { token }
      }
    `;

    query FetchDashboard {
      dashboard { id name stats }
    }

    mutation UpdateProfile($name: String!) {
      updateProfile(name: $name) { ok }
    }

    headers["X-CSRF-Token"] = csrfMeta.content;
    headers["Authorization"] = `Bearer ${idToken}`;
    document.cookie = "_dovetale_session=" + val;
    const XSRF = "XSRF-TOKEN";
    const authType = "Authorization-Type";

    const routes = [
      {path: "/creator/signup/community_application/:token", component: SignUp},
      {path: "/settings/billing", component: Billing},
      {path: "/admin/dashboard", component: Admin},
    ];

    const ws = "wss://api.collabs.shopify.com/cable";
    const staging = "https://staging-api.collabs.shopifycloud.com/api/me";

    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakesig";
    """

    result = mine_content(mock_js)

    assert "/api/community/apply/${token}" in result["api_paths"], f"api_paths: {result['api_paths']}"
    assert "/api/users/me" in result["api_paths"], f"api_paths missing /api/users/me"

    gql_strs = " ".join(result["graphql_ops"])
    assert "LoginUser" in gql_strs or "login" in gql_strs.lower(), f"graphql_ops: {result['graphql_ops']}"
    assert "FetchDashboard" in gql_strs, f"missing FetchDashboard in: {result['graphql_ops']}"
    assert "UpdateProfile" in gql_strs, f"missing UpdateProfile in: {result['graphql_ops']}"

    auth_str = " ".join(result["auth_patterns"])
    assert "csrf" in auth_str.lower() or "CSRF" in auth_str, f"auth: {result['auth_patterns']}"

    assert any("/creator/signup" in r for r in result["routes"]), f"routes: {result['routes']}"
    assert any("/admin/dashboard" in ep for ep in result["hidden_endpoints"]), f"hidden: {result['hidden_endpoints']}"

    assert len(result["interesting_urls"]) >= 1, f"interesting_urls should find embedded URLs: {result['interesting_urls']}"

    assert len(result["tokens"]) >= 1, f"tokens: {result['tokens']}"

    # mine_bundle on a file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(mock_js)
        f.flush()
        file_result = mine_bundle(f.name)
    os.unlink(f.name)
    assert len(file_result["api_paths"]) > 0, "mine_bundle(file) should find api paths"

    # discover_bundles on mock HTML
    mock_html = """
    <html><head>
    <script src="/static/vendor.abc123.js"></script>
    <script src="/static/app.B4q2SNG5.js"></script>
    <script src="/static/polyfill.js"></script>
    <script src="/static/SurveyApp-BRik6BKG.js"></script>
    </head></html>
    """
    src_re = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
    all_srcs = src_re.findall(mock_html)
    filtered = [s for s in all_srcs if not _VENDOR_PATTERNS.search(os.path.basename(s))]
    assert "/static/app.B4q2SNG5.js" in filtered, f"filter: {filtered}"
    assert "/static/SurveyApp-BRik6BKG.js" in filtered, f"filter: {filtered}"
    assert "/static/vendor.abc123.js" not in filtered
    assert "/static/polyfill.js" not in filtered

    print("jsminer.py: selftest PASSED")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        ok = _selftest()
        sys.exit(0 if ok else 1)
    sys.exit(_main(sys.argv[1:]))
