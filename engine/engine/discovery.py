#!/usr/bin/env python3
"""
discovery.py — iterative function and relationship inventory.

Safe protocol parsers, browser capture, artifact mining, and live response
relationships are attempted as available. No schema, target type, or fixed
category is required. Expansion stops after stable rounds or an explicit
budget. Validated operations, source attempts, profiles, and unparsed
residuals stay visible; the output never claims that all functions were found.

Outputs: discovery-inventory.json and discovery-inventory.md.

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

_VALIDATED_LEVELS = {"observed", "declared"}


def _prov(level, source, evidence="", round_num=0):
    """Structured provenance dict — replaces flat provenance strings."""
    return {"level": level, "source": source, "round": round_num, "evidence": evidence}


def normalize_provenance(value):
    if isinstance(value, dict) and "level" in value:
        return value
    if isinstance(value, str):
        return {"level": value, "source": "legacy", "round": 0, "evidence": ""}
    if isinstance(value, (list, tuple)):
        return [normalize_provenance(item) for item in value]
    return {"level": "observed", "source": "unknown", "round": 0, "evidence": ""}


DISCOVERY_STABLE_ROUNDS = 2
DISCOVERY_MAX_ROUNDS = 6

# HTTP methods accepted from live Allow/error evidence
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


def _parse_openapi(body):
    try:
        return json.loads(body)
    except Exception:
        try:
            import yaml
            value = yaml.safe_load(body)
            return value if isinstance(value, dict) else None
        except Exception:
            return None


def _deref(spec, value):
    if not isinstance(value, dict):
        return value
    ref = value.get("$ref")
    if not ref:
        return value
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    current = spec
    for part in ref[2:].split("/"):
        if not isinstance(current, dict):
            return {}
        current = current.get(part.replace("~1", "/").replace("~0", "~"), {})
    return current if isinstance(current, dict) else {}


def _template_example(param):
    for key in ("example", "default"):
        if param.get(key) not in (None, ""):
            return str(param[key])
    schema = param.get("schema") or {}
    for key in ("example", "default"):
        if schema.get(key) not in (None, ""):
            return str(schema[key])
    return ""


def _discover_openapi(scope, log=print):
    """Parse JSON/YAML OpenAPI with local refs and explicit template provenance."""
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
            if code != 200:
                continue
            spec = _parse_openapi(body)
            paths = (spec or {}).get("paths")
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

            for path, path_item in paths.items():
                path_item = _deref(spec, path_item)
                for method, op in path_item.items():
                    if method not in ("get", "post", "put", "patch", "delete", "head", "options"):
                        continue
                    op = _deref(spec, op)
                    raw_params = (path_item.get("parameters") or []) + (op.get("parameters") or [])
                    params = []
                    examples = {}
                    for raw in raw_params:
                        p = _deref(spec, raw)
                        if p.get("schema"):
                            p["schema"] = _deref(spec, p["schema"])
                        params.append({"name": p.get("name", ""), "in": p.get("in", ""),
                                       "required": p.get("required", False)})
                        if p.get("in") == "path":
                            examples[p.get("name", "")] = _template_example(p)
                    concrete_path = path
                    unresolved = False
                    for name in re.findall(r"\{([^}]+)\}", path):
                        value = examples.get(name, "")
                        if value:
                            concrete_path = concrete_path.replace("{" + name + "}", value)
                        else:
                            unresolved = True
                    req_body = _deref(spec, op.get("requestBody", {}))
                    body_params = []
                    for _ct, media in (req_body.get("content") or {}).items():
                        schema = _deref(spec, (media or {}).get("schema", {}))
                        for pname, raw_schema in (schema.get("properties") or {}).items():
                            pschema = _deref(spec, raw_schema)
                            body_params.append({"name": pname, "in": "body",
                                                "type": pschema.get("type", ""),
                                                "required": pname in (schema.get("required") or [])})
                    secured = bool(op["security"]) if "security" in op else bool(spec.get("security"))
                    tags = op.get("tags", [])
                    summary = op.get("summary", "") or op.get("description", "")
                    url = base_url + concrete_path
                    if not scope.in_scope_host(url):
                        continue
                    endpoints.append({
                        "url": url, "method": method.upper(), "params": params,
                        "body_params": body_params, "auth_required": secured,
                        "tags": tags, "summary": summary[:200], "source": "openapi",
                        "confidence": "low" if unresolved else "high",
                        "provenance": _prov("declared", "openapi",
                                          "template with unresolved params" if unresolved else "OpenAPI spec path"),
                        "unresolved_template": unresolved,
                        "category": _categorize_endpoint(path, method, tags, summary),
                    })
            log(f"discovery/openapi: {host}{op_path} → '{title}', {len(paths)} path(s), "
                f"{len(endpoints)} endpoint(s) with full parameter info")
            break
    return endpoints


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
                    "provenance": _prov("observed", "error_probe", f"method {method} returns {code}"),
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
            "provenance": _prov("observed", "response_mining", "extracted from live response body"),
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
    for seed in scope.seeds[:3]:
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
                        "provenance": _prov("observed", "browser", f"captured as {ident}"),
                        "category": _categorize_endpoint(urlparse(url).path, method.lower(), [], ""),
                        "params": item.get("params", []),
                        "body_params": item.get("inputs", []),
                        "auth_required": True,
                        "note": item.get("source", ""),
                    })
                log(f"discovery/browser: captured {len(caps or [])} endpoints as {ident} from {host}")
            except Exception as e:
                log(f"discovery/browser: capture failed as {ident} ({type(e).__name__}: {e})")
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
                "provenance": _prov("declared", "graphql", "introspection query"),
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


def _observation_operations(value, base_url, scope, inherited=None, depth=0):
    """Turn nested response relationships into operations without interpreting their names."""
    if depth > 10:
        return []
    inherited = dict(inherited or {})
    operations = []
    if isinstance(value, list):
        for item in value[:100]:
            operations.extend(_observation_operations(item, base_url, scope, inherited, depth + 1))
        return operations
    if not isinstance(value, dict):
        return operations
    context = dict(inherited)
    for key in ("function", "protocol", "owner", "tenant", "role", "effects", "preconditions",
                "relationships", "logic_invariants", "sensitivity"):
        if key in value:
            context[key] = value[key]
    for key, item in value.items():
        if not isinstance(item, str) or not item.startswith(("/", "http://", "https://")):
            continue
        linked = urljoin(base_url, item)
        if not scope.in_scope_host(linked):
            continue
        method = str(value.get("method") or "GET").upper()
        if method not in METHODS_TO_PROBE:
            method = "GET"
        operation = dict(context, url=linked, method=method, source="adaptive-response",
                         confidence="high" if "method" in value else "medium",
                         provenance=_prov("declared", "adaptive_response", "documented method") if "method" in value
                         else _prov("inferred", "adaptive_response", "relationship lead"))
        raw_inputs = value.get("input") or value.get("inputs") or value.get("params") or {}
        if isinstance(raw_inputs, dict):
            raw_inputs = [dict(spec, name=name) if isinstance(spec, dict) else
                          {"name": name, "type": str(spec)} for name, spec in raw_inputs.items()]
        operation["body_params" if method != "GET" else "params"] = raw_inputs
        operations.append(operation)
    for item in value.values():
        if isinstance(item, (dict, list)):
            operations.extend(_observation_operations(item, base_url, scope, context, depth + 1))
    return operations


def _html_operations(body, base_url, scope):
    """Retain navigations, form actions, methods, and fields from arbitrary HTML."""
    from html.parser import HTMLParser

    class Parser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.references = []
            self.forms = []
            self.form = None

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "form":
                self.form = {"action": attrs.get("action", ""), "method": attrs.get("method", "GET"), "inputs": []}
            elif tag in ("input", "select", "textarea") and self.form is not None and attrs.get("name"):
                self.form["inputs"].append({"name": attrs["name"], "type": attrs.get("type", "scalar")})
            elif tag in ("a", "link", "script", "img"):
                target = attrs.get("href") or attrs.get("src")
                if target:
                    self.references.append(target)

        def handle_endtag(self, tag):
            if tag == "form" and self.form is not None:
                self.forms.append(self.form)
                self.form = None

    parser = Parser()
    try:
        parser.feed(body or "")
    except Exception:
        return []
    operations = []
    for reference in parser.references:
        linked = urljoin(base_url, reference)
        if scope.in_scope_host(linked):
            operations.append({"url": linked, "method": "GET", "source": "adaptive-html",
                               "confidence": "medium",
                               "provenance": _prov("inferred", "adaptive", "HTML link reference")})
    for form in parser.forms:
        linked = urljoin(base_url, form["action"] or base_url)
        method = str(form["method"] or "GET").upper()
        if method not in METHODS_TO_PROBE or not scope.in_scope_host(linked):
            continue
        operations.append({"url": linked, "method": method, "source": "adaptive-form",
                           "confidence": "high",
                           "provenance": _prov("declared", "html_form", f"HTML form action={method}"),
                           "params" if method == "GET" else "body_params": form["inputs"]})
    return operations


_SOFT_404_CACHE = {}


def _soft_404_fingerprint(body):
    """Content-stable fingerprint: strip digits/hex, normalize whitespace, hash."""
    if not body:
        return ""
    import hashlib
    cleaned = re.sub(r'[0-9a-f]{8,}', '', body, flags=re.IGNORECASE)
    cleaned = re.sub(r'\d+', '', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()[:4000]
    return hashlib.sha256(cleaned.encode(errors="replace")).hexdigest()[:16]


def _is_soft_404(url, code, body, headers):
    """Detect soft-404: 200 that looks like an error/login/generic page."""
    if code >= 400:
        return False
    parsed = urlparse(url)
    host = parsed.netloc or parsed.hostname or ""
    if host not in _SOFT_404_CACHE:
        rand_path = f"/{''.join(chr(ord('a') + (i * 7 + 3) % 26) for i in range(12))}-{os.getpid()}"
        ctrl_url = f"{parsed.scheme}://{host}{rand_path}"
        ctrl_code, ctrl_body, _ = _probe(ctrl_url)
        _SOFT_404_CACHE[host] = _soft_404_fingerprint(ctrl_body) if ctrl_code and ctrl_code < 500 else None
    ctrl_fp = _SOFT_404_CACHE.get(host)
    if ctrl_fp and _soft_404_fingerprint(body) == ctrl_fp:
        return True
    lower = (body or "")[:2000].lower()
    if code == 200 and any(sig in lower for sig in ("page not found", "404", "does not exist",
                                                     "sign in to continue", "login required")):
        return True
    return False


def _discover_adaptive(scope, found_endpoints, log=print):
    """Expand relationships, operations, forms, events, and behavior in live responses."""
    discovered = []
    seen = {(ep.get("method", "GET"), ep.get("url", ""),
             json.dumps(ep.get("params") or [], sort_keys=True, default=str)) for ep in found_endpoints}
    candidates = [ep for ep in found_endpoints if ep.get("url") and "{" not in ep["url"]][:60]
    for ep in candidates:
        url = ep["url"]
        code, body, headers = _probe(url)
        if not code:
            continue
        if _is_soft_404(url, code, body, headers):
            ep["confidence"] = "low"
            ep["provenance"] = _prov("unresolved", "soft_404", f"soft-404 detected ({code})")
            ep.setdefault("tags", []).append("soft-404")
            continue
        if code < 400:
            ep["status"] = code
            ep["confidence"] = "high"
            ep["provenance"] = _prov("observed", "adaptive", f"live {code} response")
        allow = headers.get("allow", "") or headers.get("Allow", "")
        for method in re.split(r"[,\s]+", allow):
            method = method.strip().upper()
            if method in METHODS_TO_PROBE and (method, url) not in {(d.get("method"), d.get("url")) for d in discovered}:
                discovered.append({"url": url, "method": method, "status": code,
                                   "source": "adaptive-allow", "confidence": "high",
                                   "provenance": _prov("observed", "adaptive", f"Allow header method {method}"),
                                   "category": "observed_operation"})
        content_type = str(headers.get("content-type", "") or headers.get("Content-Type", "")).lower()
        observed = []
        if _is_json(body):
            try:
                observed = _observation_operations(json.loads(body), url, scope)
            except json.JSONDecodeError:
                observed = []
        elif "text/event-stream" in content_type:
            ep["protocol"] = "event-stream"
            for line in (body or "").splitlines():
                if line.startswith("data:") and _is_json(line[5:]):
                    try:
                        observed.extend(_observation_operations(json.loads(line[5:].strip()), url, scope))
                    except json.JSONDecodeError:
                        continue
        elif "html" in content_type or "<html" in (body or "")[:1000].lower() or "<form" in (body or "").lower():
            observed = _html_operations(body, url, scope)
        for header in ("link", "location"):
            value = headers.get(header, "") or headers.get(header.title(), "")
            for match in re.finditer(r"<([^>]+)>|^(?!.*<)(https?://\S+|/\S*)", value):
                linked = urljoin(url, match.group(1))
                if scope.in_scope_host(linked):
                    observed.append({"url": linked, "method": "GET", "source": "adaptive-header",
                                     "confidence": "medium",
                                     "provenance": _prov("inferred", "adaptive", f"Link/Location header")})
        for operation in observed:
            key = (operation.get("method", "GET"), operation.get("url", ""),
                   json.dumps(operation.get("params") or operation.get("body_params") or [], sort_keys=True, default=str))
            if operation.get("url") and key not in seen:
                seen.add(key)
                discovered.append(operation)
    log(f"discovery/adaptive: {len(discovered)} operation(s) from live response relationships")
    return discovered


def _categorize_endpoint(path, method, tags, summary):
    """Compatibility value only; no functional category is inferred from a name."""
    return "observed_operation"


def _categorize_resource(resource_path):
    return "observed_operation"


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
                "provenance": _prov("inferred", "js_bundle", "API path extracted from JS"),
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
                "provenance": _prov("inferred", "js_bundle", "route extracted from JS"),
                "auth_required": False,
                "params": [],
                "tags": ["js-mined", "route"],
                "category": _categorize_endpoint(route, "get", [], ""),
            })

    log(f"discovery: JS bundle mining found {len(endpoints)} endpoint(s)")
    return endpoints


def _compute_coverage(inventory, not_applicable=None):
    """Measure observed operations and residuals; there is no category completeness checklist."""
    _LEGACY_PROVENANCE_OK = {"observed_in_live_traffic", "documented", "confirmed_live", "observed"}

    def validated(ep):
        prov = ep.get("provenance")
        if isinstance(prov, dict):
            if prov.get("level") in _VALIDATED_LEVELS:
                return True
        elif prov in _LEGACY_PROVENANCE_OK:
            return True
        return ep.get("confidence") in ("high", "observed", "documented")

    valid = [ep for ep in inventory if validated(ep)]
    sources = {}
    confidence_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    for ep in inventory:
        src = ep.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1
        confidence = ep.get("confidence", "unknown")
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
    dimensions = {}
    unprofiled = 0
    import target_adapters as TA
    profiles = TA.http_profiles(valid)
    profiled_ids = set()
    for profile in profiles:
        profiled_ids.add(profile.get("profile_id"))
        for dimension in profile.get("trust_dimensions") or []:
            dimensions[dimension] = dimensions.get(dimension, 0) + 1
    unprofiled = max(0, len(valid) - len(profiles))
    residuals = [{"url": ep.get("url", ""), "reason": "unvalidated_lead"}
                 for ep in inventory if ep not in valid]
    residuals += [{"url": ep.get("url", ""), "reason": "unresolved_template"}
                  for ep in valid if ep.get("unresolved_template") or "{" in (ep.get("url") or "")]
    summary = {
        "discovery_ready": bool(valid),
        "coverage_unknown": not valid,
        "total_endpoints": len(inventory),
        "validated_endpoints": len(valid),
        "lead_endpoints": len(inventory) - len(valid),
        "validated_operation_pct": round(100 * len(valid) / max(len(inventory), 1), 1),
        "profile_count": len(profiles),
        "unprofiled_operations": unprofiled,
        "trust_dimensions": dimensions,
        "residuals": residuals,
        "residual_count": len(residuals),
        "blind_spots": len(residuals) + unprofiled,
        "coverage_sources": sources,
        "confidence_breakdown": confidence_counts,
        "total_categories": 0,
        "covered_categories": 0,
        "not_applicable_categories": 0,
        "coverage_pct": round(100 * len(valid) / max(len(inventory), 1), 1),
        "uncovered_categories": [],
    }
    return {"_summary": summary, "function_profiles": profiles}


def _detect_program_type(scope, log=print):
    """Observe representation capabilities without assigning a product or target type."""
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

        content_type = str((hdrs or {}).get("content-type", "") or (hdrs or {}).get("Content-Type", "")).lower()


        if "html" in content_type or re.search(r"<html|<body|<form", body or "", re.I):
            traits.add("markup")
        if re.search(r"<script|fetch\s*\(|xmlhttprequest|websocket\s*\(", body or "", re.I):
            traits.add("executable_client")
        if "json" in content_type or _is_json(body):
            traits.add("structured_data")
            try:
                document = json.loads(body)
                if isinstance(document, dict) and isinstance(document.get("paths"), dict):
                    traits.add("operation_document")
                if isinstance(document, dict) and ("__schema" in body or "__typename" in body):
                    traits.add("schema_capable_operation")
            except json.JSONDecodeError:
                traits.add("unparsed_structured_data")
        if "text/event-stream" in content_type:
            traits.add("event_data")


    method_priority = {"openapi": 20, "adaptive": 60, "error_discovery": 40,
                       "response_mining": 55, "browser_capture": 30, "graphql": 20, "js_bundle": 35}
    if "markup" in traits:
        method_priority["browser_capture"] = 80
    if "executable_client" in traits:
        method_priority.update(js_bundle=85, browser_capture=85)
    if "structured_data" in traits:
        method_priority.update(adaptive=85, response_mining=80)
    if "operation_document" in traits:
        method_priority["openapi"] = 95
    if "schema_capable_operation" in traits:
        method_priority["graphql"] = 90
    if "event_data" in traits:
        method_priority["adaptive"] = 90
    log(f"discovery: observed response capabilities={sorted(traits)}")
    return {"type": "observed", "traits": sorted(traits),
            "method_priority": method_priority, "seed_responses": seed_responses}


def discover(slug, scope, base=DEFAULT_BASE, log=print, allow_intrusive=False):
    """Run the full discovery pipeline. Adapts methods based on detected program type."""
    # Scope guard — ensures netget enforces scope even when called from CLI
    try:
        import netget
        netget.set_scope_guard(scope, allow_intrusive=allow_intrusive)
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

    inventory = [{"url": url, "method": "GET", "status": response[0], "source": "seed-observation",
                  "confidence": "high",
                  "provenance": _prov("observed", "seed_observation", "live seed response")}
                 for url, response in prog_info.get("seed_responses", {}).items()
                 if response[0] and response[0] < 400 and scope.in_scope_host(url)]
    source_counts = {"seed_observation": len(inventory)}
    methods = [
        ("openapi", _discover_openapi),
        ("js_bundle", _discover_js_bundles),
        ("browser_capture", lambda s, **kw: _discover_browser_capture(s, slug, base, **kw)),
        ("graphql", _discover_graphql),
    ]
    methods.sort(key=lambda method: priorities.get(method[0], 50), reverse=True)
    source_status = {}
    for method_name, method_fn in methods:
        try:
            eps = method_fn(scope, log=log)
            inventory.extend(eps)
            source_counts[method_name] = source_counts.get(method_name, 0) + len(eps)
            source_status[method_name] = "completed"
        except ImportError as exc:
            source_status[method_name] = "unavailable"
            log(f"discovery/{method_name}: unavailable ({exc})")
        except Exception as exc:
            source_counts.setdefault(method_name, 0)
            source_status[method_name] = "failed"
            log(f"discovery/{method_name}: failed ({type(exc).__name__}: {exc})")

    def operation_keys(items):
        return {(ep.get("method", "GET"), ep.get("url", ""),
                 json.dumps(ep.get("params") or [], sort_keys=True, default=str))
                for ep in items if ep.get("url")}

    stable_rounds = 0
    rounds = 0
    max_rounds = int(os.environ.get("HUNT_DISCOVERY_MAX_ROUNDS", str(DISCOVERY_MAX_ROUNDS)))
    budget_s = int(os.environ.get("HUNT_DISCOVERY_BUDGET_SEC", "300"))
    convergence = "stable"
    for rounds in range(1, max_rounds + 1):
        if time.time() - t0 >= budget_s:
            convergence = "budget"
            break
        before = operation_keys(inventory)
        for method_name, probe in (
                ("adaptive", lambda: _discover_adaptive(scope, inventory, log=log)),
                ("error_discovery", lambda: _discover_error_based(scope, inventory, log=log, allow_intrusive=allow_intrusive)),
                ("response_mining", lambda: _discover_from_responses(scope, inventory, log=log))):
            try:
                eps = probe()
                inventory.extend(eps)
                source_counts[method_name] = source_counts.get(method_name, 0) + len(eps)
                source_status[method_name] = "completed"
            except Exception as exc:
                source_status[method_name] = "failed"
                log(f"discovery/{method_name}: failed ({type(exc).__name__}: {exc})")
        seen = set()
        deduped = []
        for ep in inventory:
            key = (ep.get("url", ""), ep.get("method", "GET"),
                   json.dumps(ep.get("params") or [], sort_keys=True, default=str))
            if key not in seen:
                seen.add(key)
                deduped.append(ep)
        inventory = deduped
        added = len(operation_keys(inventory) - before)
        stable_rounds = stable_rounds + 1 if added == 0 else 0
        log(f"discovery/convergence: round={rounds} new_operations={added} stable_rounds={stable_rounds}")
        if stable_rounds >= DISCOVERY_STABLE_ROUNDS:
            break
    else:
        convergence = "round_limit"

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

    coverage = _compute_coverage(inventory, getattr(scope, "discovery_not_applicable", {}))
    coverage["_summary"].update({
        "required_methods": [], "failed_required_methods": [],
        "source_status": source_status, "convergence": convergence,
        "discovery_rounds": rounds, "stable_rounds": stable_rounds,
        "failed_sources": sorted(name for name, status in source_status.items() if status == "failed"),
        "unavailable_sources": sorted(name for name, status in source_status.items() if status == "unavailable"),
    })
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
        "source_status": source_status,
        "convergence": convergence,
        "discovery_rounds": rounds,
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
    log(f"discovery: DONE in {elapsed}s — {summary['validated_endpoints']} validated operation(s), "
        f"{summary['profile_count']} profile(s), {summary['residual_count']} residual(s), "
        f"convergence={convergence}, rounds={rounds}")

    if not summary["discovery_ready"]:
        log("discovery: GATE FAIL — no validated operation. Guessed paths remain leads; hunting stays blocked.")
    elif summary["residual_count"] or summary["failed_sources"] or summary["unavailable_sources"]:
        log("discovery: PARTIAL — residuals, failed sources, or unavailable capabilities remain visible")

    return result


def _write_markdown(result, path):
    """Write a human-readable discovery summary."""
    inv = result.get("inventory", [])
    cov = result.get("coverage", {})
    summary = cov.get("_summary", {})
    sources = result.get("sources", {})

    lines = [
        f"# Discovery Inventory — {result.get('slug', '?')}", "",
        f"**Time:** {result.get('timestamp', '?')} ({result.get('elapsed_seconds', '?')}s)",
        f"**Validated operations:** {summary.get('validated_endpoints', 0)}",
        f"**Function profiles:** {summary.get('profile_count', 0)}",
        f"**Convergence:** {result.get('convergence', '?')} after {result.get('discovery_rounds', 0)} round(s)",
        f"**Residuals:** {summary.get('residual_count', 0)}", "",
        "## Source attempts", "",
    ]
    statuses = result.get("source_status") or {}
    for src in sorted(set(sources) | set(statuses)):
        lines.append(f"- **{src}:** {sources.get(src, 0)} operation(s) [{statuses.get(src, 'unknown')}]")
    lines += ["", "## Trust dimensions", ""]
    for name, count in sorted((summary.get("trust_dimensions") or {}).items()):
        lines.append(f"- **{name}:** {count} profile(s)")
    lines += ["", "## Residuals", ""]
    for residual in summary.get("residuals") or []:
        lines.append(f"- `{residual.get('url', '')}` — {residual.get('reason', 'unparsed')}")
    lines += ["", "## Operations", ""]
    for ep in inv:
        method = ep.get("method", "GET")
        url = ep.get("url", "")
        note = ep.get("summary", "") or ep.get("note", "")
        line = f"- `{method}` `{url}`"
        if note:
            line += f" — {note[:100]}"
        if ep.get("source"):
            line += f" _{ep['source']}_"
        lines.append(line)
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
        if ep.get("unresolved_template"):
            item["unresolved_template"] = True
            item["blocked_reason"] = "unresolved_path_template"
        items.append(item)
    return items


def _discovery_priority(ep):
    """Rank observed impact and unresolved trust, never a functional category name."""
    import function_profile as FP
    return FP.impact_score(FP.from_endpoint(ep))


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
    print(f"Validated operations: {cov.get('validated_endpoints', 0)}")
    print(f"Function profiles: {cov.get('profile_count', 0)}")
    print(f"Residuals: {cov.get('residual_count', 0)}")
    print(f"Convergence: {inv.get('convergence', '?')} ({inv.get('discovery_rounds', 0)} rounds)")
    print(f"Timestamp: {inv.get('timestamp', '?')}")
    for name, status in (inv.get("source_status") or {}).items():
        print(f"  {name}: {status}")
    return 0


def _cmd_selftest(_a):
    """Basic self-test."""
    assert _categorize_endpoint("/anything", "post", [], "") == "observed_operation"
    test_inv = [
        {"url": "/unvalidated", "source": "lead", "confidence": "low"},
        {"url": "/one", "source": "openapi", "confidence": "high"},
        {"url": "/two", "source": "browser-capture", "confidence": "high"},
    ]
    cov = _compute_coverage(test_inv)
    assert cov["_summary"]["validated_endpoints"] == 2
    assert cov["_summary"]["residual_count"] == 1
    assert cov["_summary"]["total_categories"] == 0
    assert cov["_summary"]["profile_count"] == 2
    assert cov["_summary"]["confidence_breakdown"]["high"] == 2
    assert cov["_summary"]["confidence_breakdown"]["low"] == 1

    big_api = [{"url": f"/operation/{i}", "source": "openapi", "confidence": "high"} for i in range(50)]
    big_cov = _compute_coverage(big_api)
    assert big_cov["_summary"]["discovery_ready"] is True
    assert big_cov["_summary"]["validated_operation_pct"] == 100.0
    assert big_cov["_summary"]["profile_count"] == 50

    guessed = [{"url": f"/api/{i}", "confidence": "low",
                "provenance": _prov("unresolved", "guessed", "common path probe")} for i in range(15)]
    guessed_cov = _compute_coverage(guessed)
    assert guessed_cov["_summary"]["discovery_ready"] is False
    assert guessed_cov["_summary"]["coverage_unknown"] is True
    tiny_cov = _compute_coverage([{"url": "/x"}])
    assert tiny_cov["_summary"]["coverage_unknown"] is True

    high_ep = {"auth_required": True, "method": "POST", "body_params": [{"name": "x"}]}
    low_ep = {"method": "GET"}
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
