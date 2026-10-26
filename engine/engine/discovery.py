#!/usr/bin/env python3
"""
discovery.py — exhaustive function/endpoint inventory before any testing.

The #1 gap in bug bounty hunting: testing begins before the full surface is mapped.
This module ensures EVERY function, endpoint, role, and boundary is discovered
before a single test runs. "No function left behind."

Discovery methods (all used, not just one):
  1. OpenAPI/Swagger schema parsing
  2. JS bundle mining (routes, API calls, feature flags)
  3. Browser capture (authenticated SPA XHR/fetch)
  4. Platform probing (.well-known, robots, actuator, debug)
  5. Authenticated exploration (walk every role's view)
  6. GraphQL introspection (full schema)
  7. Response mining (linked resources, IDs, nested endpoints)
  8. Error-based discovery (405 methods, partial 404s)
  9. Documentation/changelog crawl
  10. Feature-flag enumeration

Outputs:
  discovery-inventory.json — structured inventory of ALL discovered functions
  discovery-inventory.md  — human-readable summary

CLI:
  python3 engine/engine/discovery.py discover --slug <program> [--base <dir>]
  python3 engine/engine/discovery.py show --slug <program>
  python3 engine/engine/discovery.py selftest
"""
import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlparse, urljoin

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# Categories of functions to discover — the checklist
FUNCTION_CATEGORIES = [
    "ui_features",           # buttons, forms, modals, tabs, workflows
    "api_endpoints",         # REST, GraphQL, WebSocket, gRPC, internal
    "user_roles",            # admin, member, viewer, guest, API consumer, service account
    "auth_mechanisms",       # cookies, JWT, OAuth, API keys, SAML, MFA
    "org_boundaries",        # orgs, projects, teams, workspaces, permissions
    "sharing_flows",         # project sharing, transfers, invitations, collaboration
    "integration_points",    # webhooks, OAuth apps, third-party, imports/exports
    "storage_operations",    # CRUD on every resource, file upload/download
    "admin_endpoints",       # actuator, debug, metrics, health, console, internal
    "billing_flows",         # subscriptions, usage limits, spending controls
    "credential_management", # API keys, tokens, secrets, connection strings, passwords
]

# Paths that reveal admin/internal/debug surface
ADMIN_PROBE_PATHS = [
    "/admin", "/admin/", "/dashboard", "/console", "/internal",
    "/debug", "/__debug__", "/_debug", "/trace", "/trace.axd",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/configprops", "/actuator/mappings", "/actuator/metrics",
    "/metrics", "/health", "/status", "/info", "/ready", "/live",
    "/server-status", "/server-info", "/.env", "/.git/HEAD",
    "/wp-admin", "/wp-login.php", "/elmah.axd",
    "/graphql", "/graphiql", "/playground", "/altair",
    "/swagger", "/swagger-ui", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/v3/api-docs",
    "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/_next/data", "/__nextjs_original-stack-frame",
    "/rails/info", "/rails/mailers",
    "/phpinfo.php", "/server-status",
    "/manage", "/management", "/monitoring",
]

# API version prefixes to try
API_PREFIXES = ["/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3", "/rest", "/gw"]

# Common resource paths that exist on most web apps
RESOURCE_PATHS = [
    "/users", "/accounts", "/organizations", "/orgs", "/teams", "/projects",
    "/workspaces", "/groups", "/members", "/roles", "/permissions",
    "/invitations", "/invites", "/transfers", "/sharing",
    "/settings", "/preferences", "/notifications", "/webhooks",
    "/integrations", "/connections", "/apps", "/oauth",
    "/api-keys", "/tokens", "/credentials", "/secrets",
    "/billing", "/subscriptions", "/invoices", "/payments", "/usage",
    "/files", "/uploads", "/storage", "/buckets", "/objects",
    "/databases", "/tables", "/schemas", "/queries",
    "/functions", "/deployments", "/endpoints", "/domains",
    "/branches", "/environments", "/releases", "/versions",
    "/logs", "/audit", "/events", "/activity",
    "/reports", "/exports", "/imports",
    "/search", "/filters", "/tags", "/labels",
    "/comments", "/reviews", "/feedback",
    "/support", "/tickets",
]

# HTTP methods to try on discovered endpoints
METHODS_TO_PROBE = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def _eng_dir(slug, base):
    return os.path.join(os.path.expanduser(base), slug)


def _probe(url, method="GET", timeout=12):
    """GET/HEAD via the shared transport."""
    try:
        import netget
        code, body, headers = netget.get(
            url, method=method, timeout=timeout,
            ident=os.environ.get("HUNT_RECON_IDENT") or None,
            slug=os.environ.get("HUNT_TARGET_SLUG") or None)
        return int(code or 0), body or "", headers or {}
    except Exception:
        return 0, "", {}


def _is_json(body):
    b = (body or "").lstrip()
    return b[:1] in ("{", "[")


def _extract_links_from_json(body, base_url, scope):
    """Extract URLs and resource references from JSON responses."""
    urls = set()
    try:
        data = json.loads(body)
    except Exception:
        return urls

    def _walk(obj, depth=0):
        if depth > 8:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    if v.startswith(("http://", "https://")) and scope.in_scope_host(v):
                        urls.add(v)
                    elif v.startswith("/") and len(v) > 1 and not v.startswith("//"):
                        full = urljoin(base_url, v)
                        if scope.in_scope_host(full):
                            urls.add(full)
                elif isinstance(v, (dict, list)):
                    _walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:50]:
                _walk(item, depth + 1)
    _walk(data)
    return urls


def _discover_methods(url, known_method="GET"):
    """Try OPTIONS and common methods to find what an endpoint accepts."""
    methods = set()
    code, body, headers = _probe(url, method="OPTIONS")
    if code and 200 <= code < 400:
        allow = headers.get("allow", "") or headers.get("Allow", "")
        if allow:
            for m in allow.split(","):
                m = m.strip().upper()
                if m in METHODS_TO_PROBE:
                    methods.add(m)
    if not methods:
        methods.add(known_method)
    return sorted(methods)


def _discover_openapi(scope, log=print):
    """Parse OpenAPI/Swagger specs for complete endpoint inventory."""
    endpoints = []
    openapi_paths = [
        "/openapi.json", "/swagger.json", "/api/openapi.json", "/v1/openapi.json",
        "/api-docs", "/swagger/v1/swagger.json", "/api/v1/openapi.json",
        "/v2/api-docs", "/v3/api-docs", "/swagger.yaml", "/openapi.yaml",
    ]
    for seed in scope.seeds:
        host = seed.rstrip("/")
        if "://" not in host:
            host = "https://" + host
        for op_path in openapi_paths:
            code, body = _probe(host + op_path)[:2]
            if code != 200 or not body.lstrip().startswith("{"):
                continue
            try:
                spec = json.loads(body)
            except Exception:
                continue
            paths = spec.get("paths")
            if not paths:
                continue
            title = spec.get("info", {}).get("title", "API")
            servers = spec.get("servers", [])
            base_url = host
            if servers and isinstance(servers[0], dict):
                srv = servers[0].get("url", "")
                if srv.startswith("http"):
                    base_url = srv.rstrip("/")
                elif srv.startswith("/"):
                    base_url = host + srv.rstrip("/")

            for path, methods in paths.items():
                for method, op in methods.items():
                    if method not in ("get", "post", "put", "patch", "delete", "head", "options"):
                        continue
                    params = []
                    for p in op.get("parameters", []):
                        params.append({
                            "name": p.get("name", ""),
                            "in": p.get("in", ""),
                            "required": p.get("required", False),
                        })
                    # Also check requestBody for POST/PUT/PATCH
                    req_body = op.get("requestBody", {})
                    body_params = []
                    if req_body:
                        content = req_body.get("content", {})
                        for ct, schema_ref in content.items():
                            schema = schema_ref.get("schema", {})
                            if schema.get("properties"):
                                for pname, pschema in schema["properties"].items():
                                    body_params.append({
                                        "name": pname,
                                        "in": "body",
                                        "type": pschema.get("type", ""),
                                        "required": pname in (schema.get("required") or []),
                                    })

                    secured = bool(op.get("security") or spec.get("security"))
                    tags = op.get("tags", [])
                    summary = op.get("summary", "") or op.get("description", "")

                    endpoints.append({
                        "url": base_url + path,
                        "method": method.upper(),
                        "params": params,
                        "body_params": body_params,
                        "auth_required": secured,
                        "tags": tags,
                        "summary": summary[:200],
                        "source": "openapi",
                        "confidence": "high",
                        "provenance": "documented",
                        "category": _categorize_endpoint(path, method, tags, summary),
                    })

            log(f"discovery/openapi: {host}{op_path} → '{title}', {len(paths)} path(s), "
                f"{len(endpoints)} endpoint(s) with full parameter info")
            break
    return endpoints


def _discover_admin_internal(scope, log=print):
    """Probe for admin, debug, internal, and monitoring endpoints."""
    found = []
    for seed in scope.seeds:
        u = urlparse(seed if "://" in seed else "https://" + seed)
        base = f"{u.scheme or 'https'}://{u.hostname}" + (f":{u.port}" if u.port else "")
        for path in ADMIN_PROBE_PATHS:
            code, body, headers = _probe(base + path)
            if code and 200 <= code < 400 and code != 404:
                content_type = (headers.get("content-type") or "").lower()
                is_html_shell = bool(re.search(r'<!doctype html|<html[\s>]', (body or "")[:400], re.I))
                # Skip SPA catch-all HTML shells
                if is_html_shell and "json" not in content_type and path not in ("/admin", "/dashboard", "/console"):
                    continue
                found.append({
                    "url": base + path,
                    "method": "GET",
                    "status": code,
                    "source": "admin-probe",
                    "confidence": "low",
                    "provenance": "guessed_common_path",
                    "category": "admin_endpoints",
                    "content_type": content_type[:100],
                })
        log(f"discovery/admin: probed {len(ADMIN_PROBE_PATHS)} paths on {base}, "
            f"{len(found)} live admin/internal endpoint(s)")
    return found


def _discover_api_resources(scope, log=print):
    """Systematically probe common resource paths under each API prefix."""
    found = []
    for seed in scope.seeds:
        u = urlparse(seed if "://" in seed else "https://" + seed)
        base = f"{u.scheme or 'https'}://{u.hostname}" + (f":{u.port}" if u.port else "")
        probed = 0
        for prefix in API_PREFIXES:
            for resource in RESOURCE_PATHS:
                url = base + prefix + resource
                code, body, headers = _probe(url)
                probed += 1
                if not code or code in (404, 410, 405, 502, 503):
                    continue
                # Skip SPA catch-all
                if code == 200 and not _is_json(body) and re.search(
                        r'<!doctype html|<html[\s>]', (body or "")[:400], re.I):
                    continue
                content_type = (headers.get("content-type") or "").lower()
                found.append({
                    "url": url,
                    "method": "GET",
                    "status": code,
                    "source": "resource-probe",
                    "confidence": "low",
                    "provenance": "guessed_common_path",
                    "category": _categorize_resource(resource),
                    "content_type": content_type[:100],
                    "has_data": bool(body and len(body) > 2 and body.strip() not in ("[]", "{}", "null", "")),
                })
                # Mine links from JSON responses
                if _is_json(body) and scope:
                    for linked in _extract_links_from_json(body, url, scope):
                        if linked not in {f["url"] for f in found}:
                            found.append({
                                "url": linked,
                                "method": "GET",
                                "source": "response-mining",
                                "confidence": "high",
                                "provenance": "observed_in_live_traffic",
                                "category": _categorize_endpoint(urlparse(linked).path, "get", [], ""),
                            })
        log(f"discovery/resources: probed {probed} resource paths on {base}, "
            f"{len(found)} live endpoint(s)")
    return found


def _discover_error_based(scope, found_endpoints, log=print, allow_intrusive=False):
    """Use error responses to discover hidden methods and parameters.

    When allow_intrusive is False (default), only safe/read-only methods (OPTIONS, HEAD)
    are probed. State-changing methods (POST, PUT, PATCH, DELETE) require explicit opt-in.
    """
    new_findings = []
    safe_methods = ["OPTIONS", "HEAD"]
    intrusive_methods = ["POST", "PUT", "PATCH", "DELETE"]
    probe_methods = safe_methods + (intrusive_methods if allow_intrusive else [])
    sampled = found_endpoints[:30]
    for ep in sampled:
        url = ep.get("url", "")
        if not url:
            continue
        for method in probe_methods:
            if method == ep.get("method"):
                continue
            code, body, _ = _probe(url, method=method)
            if code and code not in (404, 405, 501, 0):
                new_findings.append({
                    "url": url,
                    "method": method,
                    "status": code,
                    "source": "error-discovery",
                    "confidence": "high",
                    "provenance": "confirmed_live",
                    "category": ep.get("category", "api_endpoints"),
                    "note": f"method {method} returns {code} (not 405)",
                })
    if new_findings:
        log(f"discovery/error: found {len(new_findings)} additional method(s) on existing endpoints")
    return new_findings


def _discover_from_responses(scope, found_endpoints, log=print):
    """Mine JSON responses from discovered endpoints for linked resources."""
    new_urls = set()
    known_urls = {ep.get("url", "") for ep in found_endpoints}
    sampled = [ep for ep in found_endpoints
               if ep.get("has_data") or ep.get("source") in ("openapi", "response-mining")][:20]
    for ep in sampled:
        url = ep.get("url", "")
        if not url:
            continue
        code, body, _ = _probe(url)
        if not code or code >= 400 or not _is_json(body):
            continue
        for linked in _extract_links_from_json(body, url, scope):
            if linked not in known_urls and linked not in new_urls:
                new_urls.add(linked)
    results = []
    for url in sorted(new_urls):
        results.append({
            "url": url,
            "method": "GET",
            "source": "response-mining-deep",
            "confidence": "high",
            "provenance": "observed_in_live_traffic",
            "category": _categorize_endpoint(urlparse(url).path, "get", [], ""),
        })
    if results:
        log(f"discovery/responses: mined {len(results)} new endpoint(s) from response bodies")
    return results


def _discover_browser_capture(scope, slug, base, log=print):
    """Run authenticated browser capture to discover SPA-generated API calls."""
    found = []
    try:
        import browser
    except ImportError:
        log("discovery/browser: browser.py not available — skipping SPA capture")
        return found
    for seed in scope.seeds:
        host = seed.rstrip("/")
        if "://" not in host:
            host = "https://" + host
        for ident in ("A", "B"):
            try:
                caps = browser.capture(
                    url=host, slug=slug, ident=ident,
                    scope_hosts=[urlparse(host).hostname],
                    scope=scope)
                for item in (caps or []):
                    url = item.get("url", "")
                    if not url or not scope.in_scope_host(url):
                        continue
                    method = (item.get("method") or "GET").upper()
                    found.append({
                        "url": url,
                        "method": method,
                        "source": f"browser-capture/{ident}",
                        "confidence": "high",
                        "provenance": "observed_in_live_traffic",
                        "category": _categorize_endpoint(urlparse(url).path, method.lower(), [], ""),
                        "params": item.get("params", []),
                        "body_params": item.get("inputs", []),
                        "auth_required": True,
                        "note": item.get("source", ""),
                    })
                log(f"discovery/browser: captured {len(caps or [])} endpoints as {ident} from {host}")
            except Exception as e:
                log(f"discovery/browser: capture failed as {ident} ({type(e).__name__}: {e})")
        break  # Only try one seed
    return found


def _discover_graphql(scope, log=print):
    """Run GraphQL introspection to discover queries and mutations."""
    found = []
    try:
        import recon
        if not hasattr(recon, 'graphql_recon'):
            log("discovery/graphql: recon.graphql_recon not available")
            return found
    except ImportError:
        log("discovery/graphql: recon module not available — skipping GraphQL")
        return found
    try:
        gql_result = recon.graphql_recon(scope, log=log)
        for item in (gql_result or []):
            url = item.get("url", "")
            if not url:
                seed = (getattr(scope, "seeds", None) or [""])[0]
                host = seed.rstrip("/") if seed else ""
                if host and "://" not in host:
                    host = "https://" + host
                url = (host + "/graphql") if host else "/graphql"
            found.append({
                "url": url,
                "method": item.get("method", "POST"),
                "source": "graphql-introspection",
                "confidence": "high",
                "provenance": "documented",
                "category": "api_endpoints",
                "params": item.get("params", []),
                "note": item.get("name", "") or item.get("summary", ""),
                "auth_required": item.get("auth_required", False),
                "tags": ["graphql"],
            })
        log(f"discovery/graphql: introspection found {len(gql_result or [])} operations")
    except Exception as e:
        log(f"discovery/graphql: introspection failed ({type(e).__name__}: {e})")
    return found


def _categorize_endpoint(path, method, tags, summary):
    """Categorize an endpoint into one of the function categories."""
    p = (path or "").lower()
    s = (summary or "").lower()
    tag_str = " ".join(t.lower() for t in (tags or []))
    combined = p + " " + s + " " + tag_str

    if any(k in combined for k in ("admin", "manage", "internal", "debug", "actuator", "metrics")):
        return "admin_endpoints"
    if any(k in combined for k in ("auth", "login", "signin", "signup", "register", "oauth", "token", "session", "sso", "saml", "mfa", "2fa", "password", "reset")):
        return "auth_mechanisms"
    if any(k in combined for k in ("org", "organization", "team", "workspace", "member", "role", "permission", "group")):
        return "org_boundaries"
    if any(k in combined for k in ("share", "transfer", "invite", "invitation", "collaborat")):
        return "sharing_flows"
    if any(k in combined for k in ("webhook", "integration", "connect", "import", "export", "oauth/app")):
        return "integration_points"
    if any(k in combined for k in ("file", "upload", "storage", "bucket", "object", "download", "attachment")):
        return "storage_operations"
    if any(k in combined for k in ("billing", "subscription", "invoice", "payment", "usage", "spending", "plan", "pricing")):
        return "billing_flows"
    if any(k in combined for k in ("key", "token", "credential", "secret", "connection_uri", "password")):
        return "credential_management"
    if any(k in combined for k in ("user", "account", "profile", "setting", "preference", "notification")):
        return "user_roles"
    return "api_endpoints"


def _categorize_resource(resource_path):
    """Categorize a resource path."""
    return _categorize_endpoint(resource_path, "get", [], "")


def _discover_js_bundles(scope, log=print):
    """Phase 8: Mine JS bundles for API endpoints, routes, and auth patterns."""
    endpoints = []
    try:
        import jsminer
    except ImportError:
        log("discovery: jsminer not available — skipping JS bundle mining")
        return endpoints

    seeds = getattr(scope, "seeds", []) or []
    for seed in seeds[:5]:
        url = seed if seed.startswith("http") else f"https://{seed}"
        u = urlparse(url)
        seed_base = f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
        log(f"discovery: mining JS bundles from {url}")
        try:
            result = jsminer.mine_all(url, scope=scope)
        except Exception as exc:
            log(f"discovery: jsminer error on {url}: {exc}")
            continue

        for api_path in result.get("api_paths", []):
            full_url = f"{seed_base}{api_path}" if api_path.startswith("/") else api_path
            endpoints.append({
                "url": full_url,
                "method": "GET",
                "source": "js_bundle",
                "confidence": "medium",
                "provenance": "inferred_from_js",
                "auth_required": False,
                "params": [],
                "tags": ["js-mined"],
                "category": _categorize_endpoint(api_path, "get", [], ""),
            })

        for route in result.get("routes", []):
            full_url = f"{seed_base}{route}" if route.startswith("/") else route
            endpoints.append({
                "url": full_url,
                "method": "GET",
                "source": "js_bundle",
                "confidence": "medium",
                "provenance": "inferred_from_js",
                "auth_required": False,
                "params": [],
                "tags": ["js-mined", "route"],
                "category": _categorize_endpoint(route, "get", [], ""),
            })

    log(f"discovery: JS bundle mining found {len(endpoints)} endpoint(s)")
    return endpoints


def _compute_coverage(inventory):
    """Compute discovery coverage from endpoint depth, with category breadth as a bonus.

    The primary signal is endpoint depth — how many distinct endpoints were found
    relative to the minimum threshold. Category breadth adds up to 10% bonus to
    reward diverse discovery, but a pure API with 300 endpoints and only 2 categories
    is NOT penalized.

    When fewer than 5 endpoints exist and fewer than 2 categories, coverage is
    reported as unknown rather than a fictional percentage.
    """
    coverage = {}
    for cat in FUNCTION_CATEGORIES:
        items = [ep for ep in inventory if ep.get("category") == cat]
        coverage[cat] = {
            "count": len(items),
            "endpoints": [ep.get("url", "") for ep in items[:10]],
            "covered": len(items) > 0,
        }
    total_cats = len(FUNCTION_CATEGORIES)
    covered_cats = sum(1 for c in coverage.values() if c["covered"])
    total_eps = len(inventory)
    uncovered = [cat for cat in FUNCTION_CATEGORIES if not coverage.get(cat, {}).get("covered")]
    blind_spots = len(uncovered)

    # Source provenance breakdown
    sources = {}
    for ep in inventory:
        src = ep.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1

    # Confidence breakdown
    confidence_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    for ep in inventory:
        c = ep.get("confidence", "unknown")
        confidence_counts[c] = confidence_counts.get(c, 0) + 1

    # Coverage formula: endpoint depth is primary (90%), category breadth is bonus (10%)
    min_eps = max(1, int(os.environ.get("HUNT_MIN_DISCOVERY_ENDPOINTS", "15")))
    coverage_unknown = total_eps < 5 and covered_cats < 2

    if coverage_unknown:
        coverage_pct = 0.0
    else:
        depth_score = min(100.0, 100.0 * total_eps / min_eps)
        breadth_bonus = 10.0 * (covered_cats / total_cats) if total_cats else 0.0
        coverage_pct = round(min(100.0, 0.9 * depth_score + breadth_bonus), 1)

    coverage["_summary"] = {
        "total_categories": total_cats,
        "covered_categories": covered_cats,
        "coverage_pct": coverage_pct,
        "coverage_unknown": coverage_unknown,
        "total_endpoints": total_eps,
        "blind_spots": blind_spots,
        "uncovered_categories": uncovered,
        "coverage_sources": sources,
        "confidence_breakdown": confidence_counts,
    }
    return coverage


def _detect_program_type(scope, log=print):
    """Detect target type from live responses — adapts discovery methods.
    Returns dict with type, traits, and recommended method priority."""
    seeds = getattr(scope, "seeds", []) or (scope.get("seeds", []) if isinstance(scope, dict) else [])
    traits = set()
    seed_responses = {}

    for seed in seeds[:3]:
        url = seed if seed.startswith("http") else f"https://{seed}"
        try:
            code, body, hdrs = _probe(url)
            seed_responses[url] = (code, body, hdrs)
        except Exception:
            continue

        hdr_str = " ".join(f"{k}: {v}" for k, v in (hdrs or {}).items()).lower()
        body_lower = (body or "")[:10000].lower()

        if re.search(r"graphql|__typename|\/graphql", body_lower + hdr_str):
            traits.add("graphql")
        if re.search(r"__remixContext|x-remix|remix", body_lower + hdr_str):
            traits.add("spa")
            traits.add("remix")
        if re.search(r"__NEXT_DATA__|_next/static", body_lower):
            traits.add("spa")
            traits.add("nextjs")
        if re.search(r"react|vue|angular|ember|svelte", body_lower):
            traits.add("spa")
        if re.search(r"swagger|openapi|api-docs|swagger\.json", body_lower + hdr_str):
            traits.add("has_openapi")
        if re.search(r"application/json|content-type.*json", hdr_str):
            traits.add("api_first")
        if re.search(r"grpc|protobuf|application/grpc", body_lower + hdr_str):
            traits.add("grpc")
        if re.search(r"<html|<body|text/html", body_lower + hdr_str):
            traits.add("web")
        if re.search(r"wss?://|websocket|upgrade.*websocket", body_lower + hdr_str):
            traits.add("websocket")
        if re.search(r"/api/v\d|/rest/|/v\d/", body_lower):
            traits.add("versioned_api")
        if re.search(r"mobile|android|ios|app-version|x-app-id", hdr_str):
            traits.add("mobile_api")
        if re.search(r"wp-content|wordpress|wp-json", body_lower + hdr_str):
            traits.add("wordpress")
        if re.search(r"rails|x-runtime|turbo-frame", hdr_str):
            traits.add("rails")
        if re.search(r"django|csrfmiddleware", body_lower + hdr_str):
            traits.add("django")
        if re.search(r"x-powered-by.*express|x-powered-by.*next", hdr_str):
            traits.add("nodejs")

    # Classify from traits — one label for logging/metadata, NOT for branching logic
    has_web = "web" in traits or "spa" in traits
    has_api = "api_first" in traits or "versioned_api" in traits
    ptype = ("spa_webapp" if "spa" in traits
             else "pure_api" if has_api and not has_web
             else "traditional_webapp" if has_web
             else "unknown")

    # Method priority — trait-driven, not type-driven. Each detected trait boosts
    # the methods most useful for it. No trait = balanced defaults.
    method_priority = {
        "openapi": 80,
        "admin_probe": 50,
        "resource_probe": 60,
        "error_discovery": 40,
        "response_mining": 55,
        "browser_capture": 30,
        "graphql": 20,
        "js_bundle": 35,
    }
    # Trait-driven boosts — each observed trait raises the methods that work best
    _TRAIT_BOOSTS = {
        "has_openapi":   {"openapi": 95},
        "spa":           {"js_bundle": 90, "browser_capture": 85},
        "graphql":       {"graphql": 95},
        "api_first":     {"openapi": 95, "resource_probe": 85, "browser_capture": 10},
        "versioned_api": {"resource_probe": 85, "openapi": 90},
        "mobile_api":    {"openapi": 90, "resource_probe": 85, "browser_capture": 10, "js_bundle": 10},
        "grpc":          {"resource_probe": 85, "browser_capture": 10, "js_bundle": 10},
        "websocket":     {"browser_capture": 85},
    }
    for trait in traits:
        for method, prio in _TRAIT_BOOSTS.get(trait, {}).items():
            if prio > method_priority.get(method, 0):
                method_priority[method] = prio

    log(f"discovery: detected program type={ptype}, traits={sorted(traits)}")
    return {
        "type": ptype,
        "traits": sorted(traits),
        "method_priority": method_priority,
        "seed_responses": seed_responses,
    }


def discover(slug, scope, base=DEFAULT_BASE, log=print, allow_intrusive=False):
    """Run the full discovery pipeline. Adapts methods based on detected program type."""
    # Scope guard — ensures netget enforces scope even when called from CLI
    try:
        import netget
        netget.set_scope_guard(scope)
    except Exception:
        pass

    eng_dir = _eng_dir(slug, base)
    os.makedirs(eng_dir, exist_ok=True)

    log(f"discovery: starting exhaustive function inventory for {slug}")
    t0 = time.time()

    # Step 0: Detect program type and adapt method priority
    prog_info = _detect_program_type(scope, log=log)
    ptype = prog_info["type"]
    traits = prog_info["traits"]
    priorities = prog_info["method_priority"]

    inventory = []
    source_counts = {}

    # Run discovery methods ordered by priority (highest first)
    methods = [
        ("openapi", _discover_openapi),
        ("admin_probe", _discover_admin_internal),
        ("resource_probe", _discover_api_resources),
        ("js_bundle", _discover_js_bundles),
        ("browser_capture", lambda s, **kw: _discover_browser_capture(s, slug, base, **kw)),
        ("graphql", _discover_graphql),
    ]
    methods.sort(key=lambda m: priorities.get(m[0], 50), reverse=True)

    for method_name, method_fn in methods:
        if priorities.get(method_name, 50) < 10:
            log(f"discovery/{method_name}: skipped (low priority for {ptype})")
            source_counts[method_name] = 0
            continue
        try:
            eps = method_fn(scope, log=log)
            inventory.extend(eps)
            source_counts[method_name] = len(eps)
            if eps:
                log(f"discovery/{method_name}: found {len(eps)} endpoint(s)")
        except Exception as e:
            log(f"discovery/{method_name}: failed ({type(e).__name__}: {e})")
            source_counts[method_name] = 0

    # Always run error-based and response-mining as they build on earlier results
    try:
        error_eps = _discover_error_based(scope, inventory, log=log, allow_intrusive=allow_intrusive)
        inventory.extend(error_eps)
        source_counts["error_discovery"] = len(error_eps)
    except Exception as e:
        log(f"discovery/error_discovery: failed ({type(e).__name__}: {e})")
        source_counts["error_discovery"] = 0

    try:
        response_eps = _discover_from_responses(scope, inventory, log=log)
        inventory.extend(response_eps)
        source_counts["response_mining"] = len(response_eps)
    except Exception as e:
        log(f"discovery/response_mining: failed ({type(e).__name__}: {e})")
        source_counts["response_mining"] = 0

    # Dedup by (url, method)
    seen = set()
    deduped = []
    for ep in inventory:
        key = (ep.get("url", ""), ep.get("method", "GET"))
        if key not in seen:
            seen.add(key)
            deduped.append(ep)
    inventory = deduped

    # Auto-detect technologies from seed responses
    detected_tech = set()
    try:
        import knowledge
        seeds = getattr(scope, "seeds", []) or (scope.get("seeds", []) if isinstance(scope, dict) else [])
        for seed in seeds[:3]:
            url = seed if seed.startswith("http") else f"https://{seed}"
            try:
                if url in prog_info.get("seed_responses", {}):
                    _, body, hdrs = prog_info["seed_responses"][url]
                else:
                    _, body, hdrs = _probe(url)
                dt = knowledge.detect_tech(headers=hdrs, body=body[:8000], url=url)
                detected_tech.update(dt)
            except Exception:
                pass
        if detected_tech:
            log(f"discovery: auto-detected tech: {sorted(detected_tech)}")
    except ImportError:
        pass

    # Compute coverage
    coverage = _compute_coverage(inventory)
    elapsed = round(time.time() - t0, 1)

    result = {
        "slug": slug,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": elapsed,
        "inventory": inventory,
        "program_type": ptype,
        "program_traits": traits,
        "coverage": coverage,
        "detected_tech": sorted(detected_tech),
        "sources": source_counts,
    }

    # Write artifacts
    inv_path = os.path.join(eng_dir, "discovery-inventory.json")
    with open(inv_path, "w") as f:
        json.dump(result, f, indent=2)
    log(f"discovery: wrote {inv_path}")

    md_path = os.path.join(eng_dir, "discovery-inventory.md")
    _write_markdown(result, md_path)
    log(f"discovery: wrote {md_path}")

    summary = coverage["_summary"]
    log(f"discovery: DONE in {elapsed}s — {summary['total_endpoints']} endpoint(s), "
        f"{summary['covered_categories']}/{summary['total_categories']} categories covered "
        f"({summary['coverage_pct']}%)")

    # Coverage gate
    if summary["coverage_pct"] < 80:
        log(f"discovery: GATE FAIL — coverage {summary['coverage_pct']}% < 80% threshold. "
            "Hunt phase will BLOCK until coverage improves. "
            "Try: authenticated browser exploration, documentation crawl, or JS bundle mining.")
        uncovered = [cat for cat, data in coverage.items()
                     if cat != "_summary" and not data.get("covered")]
        if uncovered:
            log(f"discovery: uncovered categories: {', '.join(uncovered)}")

    return result


def _write_markdown(result, path):
    """Write a human-readable discovery summary."""
    inv = result.get("inventory", [])
    cov = result.get("coverage", {})
    summary = cov.get("_summary", {})
    sources = result.get("sources", {})

    lines = [
        f"# Discovery Inventory — {result.get('slug', '?')}",
        f"",
        f"**Time:** {result.get('timestamp', '?')} ({result.get('elapsed_seconds', '?')}s)",
        f"**Total endpoints:** {summary.get('total_endpoints', 0)}",
        f"**Category coverage:** {summary.get('covered_categories', 0)}/{summary.get('total_categories', 0)} "
        f"({summary.get('coverage_pct', 0)}%)",
        f"",
        f"## Sources",
        f"",
    ]
    for src, count in sorted(sources.items(), key=lambda x: -x[1]):
        lines.append(f"- **{src}:** {count} endpoint(s)")
    lines.append("")

    lines.append("## Coverage by Category")
    lines.append("")
    for cat in FUNCTION_CATEGORIES:
        data = cov.get(cat, {})
        status = "covered" if data.get("covered") else "MISSING"
        count = data.get("count", 0)
        lines.append(f"- **{cat}:** {count} endpoint(s) [{status}]")
    lines.append("")

    # Group endpoints by category
    by_cat = {}
    for ep in inv:
        cat = ep.get("category", "api_endpoints")
        by_cat.setdefault(cat, []).append(ep)

    for cat in FUNCTION_CATEGORIES:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        lines.append(f"## {cat} ({len(eps)} endpoint(s))")
        lines.append("")
        for ep in eps[:50]:
            method = ep.get("method", "GET")
            url = ep.get("url", "")
            src = ep.get("source", "")
            note = ep.get("summary", "") or ep.get("note", "")
            line = f"- `{method}` `{url}`"
            if note:
                line += f" — {note[:100]}"
            if src:
                line += f" _{src}_"
            lines.append(line)
        if len(eps) > 50:
            lines.append(f"- ... and {len(eps) - 50} more")
        lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))


def load_inventory(slug, base=DEFAULT_BASE):
    """Load a previously saved discovery inventory."""
    path = os.path.join(_eng_dir(slug, base), "discovery-inventory.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def inventory_to_surface(inventory_data):
    """Convert discovery inventory to engine surface items for the hunt pipeline.
    Preserves rich metadata so hunt agents know WHAT to test, not just WHERE."""
    items = []
    for ep in (inventory_data or {}).get("inventory", []):
        url = ep.get("url", "")
        if not url:
            continue
        method = ep.get("method", "GET")
        item = {
            "url": url,
            "method": method,
            "vuln_class": "deep",
            "source": f"discovery/{ep.get('source', 'unknown')}",
            "priority": _discovery_priority(ep),
        }
        params = ep.get("params", [])
        if params:
            item["param"] = ",".join(p.get("name", "") for p in params[:5])
            item["params"] = [p.get("name", "") for p in params]
        body_params = ep.get("body_params", [])
        if body_params:
            item["body_params"] = [p.get("name", "") for p in body_params[:20]]
            item["body_param_types"] = {p.get("name", ""): p.get("type", "") for p in body_params[:20]}
        if ep.get("auth_required"):
            item["auth_required"] = True
        tags = ep.get("tags", [])
        if tags:
            item["tags"] = tags
        note = ep.get("summary", "") or ep.get("note", "")
        if note:
            item["note"] = note[:200]
        if ep.get("category"):
            item["category"] = ep["category"]
        if ep.get("confidence"):
            item["confidence"] = ep["confidence"]
        if ep.get("provenance"):
            item["provenance"] = ep["provenance"]
        items.append(item)
    return items


def _discovery_priority(ep):
    """Assign priority based on category and characteristics."""
    cat = ep.get("category", "api_endpoints")
    base = 50
    # High-value categories get a boost
    boosts = {
        "credential_management": 40,
        "admin_endpoints": 35,
        "org_boundaries": 30,
        "sharing_flows": 30,
        "auth_mechanisms": 25,
        "billing_flows": 25,
        "storage_operations": 20,
        "integration_points": 20,
    }
    base += boosts.get(cat, 10)
    if ep.get("auth_required"):
        base += 15
    if ep.get("body_params"):
        base += 10
    if ep.get("method", "GET") in ("POST", "PUT", "PATCH", "DELETE"):
        base += 10
    return base


# ---------------------------------------------------------------- CLI
def _cmd_discover(a):
    from scope import Scope
    sc = Scope.load(a.scope) if a.scope else None
    if not sc:
        print("ERROR: --scope required", file=sys.stderr)
        return 1
    slug = a.slug or sc.name
    result = discover(slug, sc, base=a.base)
    print(json.dumps(result.get("coverage", {}).get("_summary", {}), indent=2))
    return 0


def _cmd_show(a):
    inv = load_inventory(a.slug, base=a.base)
    if not inv:
        print(f"No discovery inventory for {a.slug}", file=sys.stderr)
        return 1
    cov = inv.get("coverage", {}).get("_summary", {})
    print(f"Slug: {a.slug}")
    print(f"Endpoints: {cov.get('total_endpoints', 0)}")
    print(f"Coverage: {cov.get('covered_categories', 0)}/{cov.get('total_categories', 0)} "
          f"({cov.get('coverage_pct', 0)}%)")
    print(f"Timestamp: {inv.get('timestamp', '?')}")
    for cat, data in inv.get("coverage", {}).items():
        if cat.startswith("_"):
            continue
        print(f"  {cat}: {data.get('count', 0)} endpoint(s)")
    return 0


def _cmd_selftest(_a):
    """Basic self-test."""
    # Test categorization
    assert _categorize_endpoint("/api/organizations/123/members", "get", [], "") == "org_boundaries"
    assert _categorize_endpoint("/auth/login", "post", [], "") == "auth_mechanisms"
    assert _categorize_endpoint("/admin/users", "get", ["admin"], "") == "admin_endpoints"
    assert _categorize_endpoint("/billing/invoices", "get", [], "") == "billing_flows"
    assert _categorize_endpoint("/files/upload", "post", [], "") == "storage_operations"
    assert _categorize_endpoint("/webhooks", "post", [], "") == "integration_points"
    assert _categorize_endpoint("/projects/transfer", "post", [], "") == "sharing_flows"
    assert _categorize_endpoint("/credentials/rotate", "post", [], "") == "credential_management"

    # Test coverage computation
    test_inv = [
        {"url": "/admin", "category": "admin_endpoints", "source": "admin-probe", "confidence": "low"},
        {"url": "/login", "category": "auth_mechanisms", "source": "openapi", "confidence": "high"},
        {"url": "/orgs", "category": "org_boundaries", "source": "browser-capture", "confidence": "high"},
    ]
    cov = _compute_coverage(test_inv)
    assert cov["_summary"]["covered_categories"] == 3
    assert cov["_summary"]["total_categories"] == len(FUNCTION_CATEGORIES)
    assert cov["admin_endpoints"]["count"] == 1
    assert not cov["billing_flows"]["covered"]
    assert "coverage_sources" in cov["_summary"]
    assert "confidence_breakdown" in cov["_summary"]
    assert cov["_summary"]["confidence_breakdown"]["high"] == 2
    assert cov["_summary"]["confidence_breakdown"]["low"] == 1

    # A pure API with many endpoints but few categories should NOT be penalized
    big_api = [{"url": f"/api/v1/resource{i}", "category": "api_endpoints",
                "source": "openapi", "confidence": "high"} for i in range(50)]
    big_cov = _compute_coverage(big_api)
    assert big_cov["_summary"]["coverage_pct"] >= 80, (
        f"50-endpoint pure API should pass 80% gate, got {big_cov['_summary']['coverage_pct']}")
    assert big_cov["_summary"]["covered_categories"] == 1

    # Unknown coverage for very sparse results
    tiny_inv = [{"url": "/x", "category": "api_endpoints"}]
    tiny_cov = _compute_coverage(tiny_inv)
    assert tiny_cov["_summary"]["coverage_unknown"] is True

    # Test priority
    high_ep = {"category": "credential_management", "auth_required": True, "method": "POST", "body_params": [{"name": "x"}]}
    low_ep = {"category": "api_endpoints", "method": "GET"}
    assert _discovery_priority(high_ep) > _discovery_priority(low_ep)

    # Test inventory_to_surface
    inv_data = {"inventory": [
        {"url": "https://api.test/users", "method": "GET", "source": "openapi", "category": "user_roles",
         "params": [{"name": "id"}], "summary": "List users"},
    ]}
    surface = inventory_to_surface(inv_data)
    assert len(surface) == 1
    assert surface[0]["source"] == "discovery/openapi"
    assert surface[0]["param"] == "id"

    print("discovery.py selftest: PASS")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="discovery")
    sp = p.add_subparsers(dest="cmd")
    d = sp.add_parser("discover")
    d.add_argument("--slug", required=True)
    d.add_argument("--scope")
    d.add_argument("--base", default=DEFAULT_BASE)
    s = sp.add_parser("show")
    s.add_argument("--slug", required=True)
    s.add_argument("--base", default=DEFAULT_BASE)
    sp.add_parser("selftest")
    a = p.parse_args(argv)
    if a.cmd == "discover":
        return _cmd_discover(a)
    elif a.cmd == "show":
        return _cmd_show(a)
    elif a.cmd == "selftest":
        return _cmd_selftest(a)
    else:
        p.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
