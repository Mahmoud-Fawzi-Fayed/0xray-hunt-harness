#!/usr/bin/env python3
"""
knowledge.py — signal-to-pattern library for dynamic hunting.

Maps endpoint signals (from testplan.analyze_endpoint) to historical
vulnerability patterns. NOT a static checklist — a reference library
the hunt agent consults to form better hypotheses from live behavior.

The agent still reasons from live bytes. This module answers:
"Given what this endpoint DOES, what has gone wrong in similar endpoints before?"
"""

import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(os.path.dirname(ENGINE), "skills")

# ---------------------------------------------------------------------------
# Pattern library — keyed by signal combinations, not vuln class names.
# Each entry describes WHAT TO LOOK FOR, not what vuln to test.
# The hunt agent reads these and decides what applies to THIS endpoint.
# ---------------------------------------------------------------------------

SIGNAL_PATTERNS = {
    # --- Identity + State changing = cross-account mutation risk ---
    ("handles_identity", "state_changing"): {
        "what_goes_wrong": [
            "Object IDs in request belong to user A but session belongs to user B — server trusts the ID",
            "Bulk/batch endpoints accept mixed-owner IDs without per-item auth check",
            "DELETE/archive operations check ownership on read but not on write",
            "Numeric or sequential IDs are guessable; UUIDs may still leak in responses",
        ],
        "first_moves": [
            "As user A, create an object. Note the ID in the response.",
            "As user B, replay the exact same mutation with A's object ID.",
            "Compare response bodies — identical structure with A's data = confirmed.",
            "Try the write path (PUT/PATCH/DELETE) even if read (GET) is blocked.",
        ],
        "evidence_bar": "Two distinct sessions, one modifying the other's object. Show both request+response pairs.",
        "skills": ["hunt-idor", "hunt-auth-bypass"],
    },

    # --- Identity + read-only = cross-account data leak ---
    ("handles_identity",): {
        "what_goes_wrong": [
            "GET endpoints return data for any ID without ownership check",
            "Pagination/listing endpoints leak other users' objects in the response",
            "Search/filter endpoints return cross-tenant results",
            "GraphQL nested resolvers return related objects without boundary checks",
        ],
        "first_moves": [
            "As user A, note an object ID from any response.",
            "As user B, request that object ID — does the server return it?",
            "Enumerate: increment/decrement numeric IDs, try UUIDs from other responses.",
            "Check if list endpoints filter by session or return everything.",
        ],
        "evidence_bar": "User B's session retrieving user A's data. Two sessions, two identities.",
        "skills": ["hunt-idor"],
    },

    # --- Financial + state_changing = payment/transaction manipulation ---
    ("financial", "state_changing"): {
        "what_goes_wrong": [
            "Price is sent client-side and server doesn't re-validate against catalog",
            "Quantity/amount can go negative (refund to attacker, charge to victim)",
            "Discount/coupon application has no server-side limit check",
            "Race condition: two concurrent purchases drain balance once but deliver twice",
            "Currency conversion exploited by switching currency mid-transaction",
            "Gift card / credit codes are sequential or short enough to brute-force",
        ],
        "first_moves": [
            "Capture a purchase/payment request. Modify amount to 0 or negative.",
            "Apply a discount code, then replay the final purchase without the discount being consumed.",
            "Send identical purchase requests concurrently (HTTP/2 single-packet for tight race window).",
            "Change currency between price-check and charge steps.",
        ],
        "evidence_bar": "Demonstrated financial impact: item obtained for wrong price, balance manipulated, or duplicate transaction.",
        "skills": ["hunt-payment-logic", "hunt-race-condition", "hunt-business-logic"],
    },

    # --- Financial (read) = billing/transaction data leak ---
    ("financial",): {
        "what_goes_wrong": [
            "Invoice/receipt endpoints return other users' financial data",
            "Transaction history accessible cross-account",
            "Billing configuration (payment methods, addresses) exposed via IDOR",
        ],
        "first_moves": [
            "Request invoices/receipts with another user's IDs.",
            "Check if billing endpoints have different auth than the main app.",
        ],
        "evidence_bar": "Another user's financial data in the response body.",
        "skills": ["hunt-idor", "hunt-payment-logic"],
    },

    # --- Auth flow = authentication/session attacks ---
    ("auth_flow",): {
        "what_goes_wrong": [
            "Password reset token is predictable (timestamp-based, sequential, short)",
            "Reset link doesn't expire or can be reused after password change",
            "Host header in reset email is attacker-controlled (poisoned reset link)",
            "Rate limiting on login/reset is per-IP only — bypassable with X-Forwarded-For",
            "OAuth state parameter missing or not validated → CSRF on auth",
            "Token exchange between services allows privilege escalation",
            "MFA can be skipped by directly hitting the post-MFA endpoint",
            "Session fixation: session ID doesn't rotate after login",
        ],
        "first_moves": [
            "Request a password reset. Inspect the token: length, charset, entropy.",
            "Replay the reset token after it's been used — does it still work?",
            "Send the reset request with a modified Host header. Check the email link.",
            "Hit the login endpoint 100 times rapidly — is there actual rate limiting?",
            "For OAuth: remove the state parameter entirely. Does the flow complete?",
        ],
        "evidence_bar": "Account takeover demonstrated, or auth bypass proven with two distinct sessions.",
        "skills": ["hunt-auth-bypass", "hunt-password-reset", "hunt-oauth", "hunt-session",
                    "hunt-2fa-bypass", "hunt-mfa-bypass"],
    },

    # --- Auth flow + elevated = admin auth bypass ---
    ("auth_flow", "elevated_privilege"): {
        "what_goes_wrong": [
            "Admin login uses same mechanism as user login but with weaker protections",
            "Admin session tokens are the same format — predict admin token from user token",
            "Admin panel relies on client-side role check (JS), server doesn't re-verify",
            "Default credentials on admin endpoints",
            "Admin API endpoints accessible with regular user session",
        ],
        "first_moves": [
            "Authenticate as regular user. Access admin endpoints with that session.",
            "Compare JWT claims between user and admin tokens — can you forge the role?",
            "Check if admin endpoints are just path-based (/admin/*) with no server auth check.",
        ],
        "evidence_bar": "Regular user performing admin-only operations. Two role levels, cross-role action.",
        "skills": ["hunt-auth-bypass", "hunt-mass-assignment"],
    },

    # --- Elevated privilege + state_changing = privilege escalation ---
    ("elevated_privilege", "state_changing"): {
        "what_goes_wrong": [
            "Role parameter in profile update is writable (mass assignment → admin)",
            "Invitation flow allows self-invite to higher role",
            "Admin-only mutations accessible with non-admin session",
            "Organization/team role can be escalated by member",
        ],
        "first_moves": [
            "Update your profile. Add role=admin, is_admin=true, permissions=all to the body.",
            "Check the invitation endpoint — can you invite yourself with elevated role?",
            "As viewer/member, call admin-only endpoints. Check response vs 403.",
        ],
        "evidence_bar": "Demonstrated role escalation: before (low role) → action → after (high role operations work).",
        "skills": ["hunt-mass-assignment", "hunt-auth-bypass"],
    },

    # --- Accepts file = upload-based attacks ---
    ("accepts_file",): {
        "what_goes_wrong": [
            "File type validation is client-side only or checks extension not magic bytes",
            "Uploaded files served from same origin → stored XSS via HTML/SVG upload",
            "Path traversal in filename overwrites server files",
            "Image processing library vulnerable to crafted image (ImageMagick, PIL)",
            "Large file upload causes DoS or storage abuse",
            "Upload endpoint doesn't check ownership — upload to another user's storage",
        ],
        "first_moves": [
            "Upload an SVG with embedded JavaScript. Access the served file — does JS execute?",
            "Upload with Content-Type: text/html but .jpg extension. How is it served?",
            "Upload with filename containing ../../../etc/passwd traversal.",
            "Upload to another user's resource (change the owner ID in the upload request).",
        ],
        "evidence_bar": "Code execution in victim context (XSS via upload), or cross-user file manipulation.",
        "skills": ["hunt-file-upload", "hunt-xss"],
    },

    # --- Accepts URL = SSRF / open redirect ---
    ("accepts_url",): {
        "what_goes_wrong": [
            "Server fetches the URL without restricting to external hosts → SSRF to internal services",
            "URL used in redirect without validation → open redirect → token theft in OAuth flows",
            "URL scheme not restricted: file://, gopher://, dict:// accepted",
            "IP-based blocklist bypassable: 0x7f000001, 0177.0.0.1, [::ffff:127.0.0.1], DNS rebinding",
            "Redirect parameter used in post-login flow → phishing/token interception",
        ],
        "first_moves": [
            "Submit url=http://169.254.169.254/latest/meta-data/ (AWS metadata).",
            "Submit url=http://127.0.0.1:PORT for common internal ports (6379, 9200, 5432).",
            "For redirect params: set to https://evil.com — does it redirect without validation?",
            "Try URL encoding, double encoding, and scheme tricks (http://evil.com@legit.com).",
            "Use an OOB server (Burp Collaborator) to confirm server-side fetch.",
        ],
        "evidence_bar": "Internal service response in output (SSRF), or demonstrated redirect to attacker domain with token/session.",
        "skills": ["hunt-ssrf", "hunt-open-redirect"],
    },

    # --- Accepts freetext = injection ---
    ("accepts_freetext",): {
        "what_goes_wrong": [
            "Input reflected in HTML without encoding → XSS",
            "Input interpolated in SQL query → SQLi",
            "Input used in template rendering → SSTI",
            "Input used in system command → command injection",
            "Input used in LDAP/NoSQL query → injection",
            "Search input reflected in error messages with extra context",
        ],
        "first_moves": [
            "Submit a canary with special chars: '\"><img/src=x onerror=alert(1)>{{7*7}}",
            "Check response: is the input reflected? Encoded? In what context (HTML/JS/attribute)?",
            "For SQL: submit ' OR 1=1-- and a valid value. Compare response times and bodies.",
            "For template: submit {{7*7}} or ${7*7} — does the response contain 49?",
            "Check error messages for stack traces, query strings, or path disclosure.",
        ],
        "evidence_bar": "XSS: payload executing in victim context. SQLi: data extraction or boolean/time difference. SSTI: template evaluation proven.",
        "skills": ["hunt-xss", "hunt-sqli", "hunt-ssti", "hunt-nosqli", "hunt-dom"],
    },

    # --- API schema (GraphQL/REST API) = API-specific attacks ---
    ("api_schema",): {
        "what_goes_wrong": [
            "GraphQL introspection enabled in production → full schema leak",
            "Deeply nested queries cause resource exhaustion (query complexity attack)",
            "Batch queries bypass rate limiting (send 100 mutations in one request)",
            "Field-level authorization missing: user can query admin-only fields",
            "Alias-based rate limit bypass: same query aliased N times in one request",
            "REST API versioning: old versions have weaker auth",
        ],
        "first_moves": [
            "GraphQL: send introspection query. If blocked, try field suggestions (__type).",
            "GraphQL: query a field you shouldn't have access to (admin fields, other user's data).",
            "GraphQL: send a deeply nested query (20+ levels) — does the server limit depth?",
            "REST: try /api/v1/ when current is /api/v3/ — does old version work with weaker auth?",
            "Check if batch operations bypass per-request rate limits.",
        ],
        "evidence_bar": "Schema leak, unauthorized data access, or demonstrated resource exhaustion / rate limit bypass.",
        "skills": ["hunt-graphql", "hunt-api-misconfig", "hunt-api-fuzzing", "hunt-api-owasp"],
    },

    # --- Realtime = WebSocket/SSE attacks ---
    ("realtime",): {
        "what_goes_wrong": [
            "WebSocket upgrade doesn't check origin → cross-site WebSocket hijacking",
            "No authentication on WebSocket messages after initial handshake",
            "Subscribe to another user's channel/room without authorization",
            "Message injection into other users' conversations",
            "Connection doesn't validate ticket/token expiry",
        ],
        "first_moves": [
            "Connect from a different origin — is the Origin header validated?",
            "After connecting, subscribe to channels with other users' IDs.",
            "Send a message to a channel you shouldn't have access to.",
            "Let the auth token expire — does the connection stay alive?",
        ],
        "evidence_bar": "Cross-origin WebSocket hijack with data exfil, or cross-user message access.",
        "skills": ["hunt-websocket"],
    },

    # --- State changing (generic) = race conditions / business logic ---
    ("state_changing",): {
        "what_goes_wrong": [
            "No idempotency check: same request processed twice = double action",
            "TOCTOU: check happens at time T1, action at T2, state changed between",
            "Concurrent requests bypass limit checks (redeem coupon twice, create extra resources)",
            "Delete + recreate race: deleted object's ID is reused",
            "State machine bypass: skip required steps by calling later endpoint directly",
        ],
        "first_moves": [
            "Send the same state-changing request twice rapidly. Is it idempotent?",
            "For limit-bound operations: send N concurrent requests via HTTP/2 single-packet.",
            "Skip intermediate steps: go directly to the 'confirm' endpoint without 'prepare'.",
            "Check if delete is hard or soft — can you access 'deleted' resources?",
        ],
        "evidence_bar": "Demonstrated double-action, limit bypass, or state machine violation with real impact.",
        "skills": ["hunt-race-condition", "hunt-business-logic"],
    },
}

# ---------------------------------------------------------------------------
# Cross-cutting patterns — apply to any endpoint regardless of signal
# ---------------------------------------------------------------------------

UNIVERSAL_CHECKS = [
    {
        "name": "CORS misconfiguration",
        "check": "Send with Origin: https://evil.com. Does Access-Control-Allow-Origin reflect it with credentials?",
        "impact": "Cross-origin data theft if ACAO reflects arbitrary origins with ACAC: true",
        "skill": "hunt-cors",
    },
    {
        "name": "CSRF on state-changing",
        "check": "Is there a CSRF token? Remove it — does the request still work?",
        "impact": "Victim visits attacker page → unwanted state change",
        "skill": "hunt-csrf",
    },
    {
        "name": "HTTP method override",
        "check": "GET request with X-HTTP-Method-Override: DELETE. Does the server honor it?",
        "impact": "Bypass method-based access controls via override headers",
        "skill": "hunt-api-misconfig",
    },
    {
        "name": "Verbose errors",
        "check": "Send malformed input. Does the error reveal stack traces, SQL, file paths?",
        "impact": "Information disclosure aiding further attacks",
        "skill": "hunt-source-leak",
    },
]

# ---------------------------------------------------------------------------
# Tech-specific patterns — activated when specific technologies are detected
# ---------------------------------------------------------------------------

TECH_PATTERNS = {
    "graphql": {
        "what_goes_wrong": [
            "Introspection enabled → full schema disclosure",
            "Nested query depth not limited → DoS",
            "Batch mutations bypass rate limits",
            "Field-level authorization missing on sensitive fields",
        ],
        "first_moves": [
            "Send __schema introspection query",
            "Test query depth limits with nested fragments",
            "Batch 50 identical mutations in one request",
        ],
        "skills": ["hunt-graphql"],
    },
    "jwt": {
        "what_goes_wrong": [
            "Algorithm confusion: RS256 → HS256 with public key as secret",
            "None algorithm accepted",
            "Weak signing secret (brute-forceable)",
            "No expiry validation / very long expiry",
            "JWK/JWKS injection in header",
        ],
        "first_moves": [
            "Decode the JWT. Check algorithm, expiry, claims.",
            "Change alg to none. Remove signature. Does it validate?",
            "Change alg to HS256. Sign with the public key.",
        ],
        "skills": ["hunt-jwt"],
    },
    "rails": {
        "what_goes_wrong": [
            "Mass assignment on model attributes (role, admin, verified)",
            "Debug endpoints left enabled in production",
            "Session cookie deserialization (older Rails)",
            "Parameter pollution with nested hashes",
        ],
        "first_moves": [
            "Add unexpected params: user[role]=admin, user[admin]=true",
            "Try /rails/info, /rails/mailers, debug endpoints",
        ],
        "skills": ["hunt-mass-assignment"],
    },
    "nextjs": {
        "what_goes_wrong": [
            "Middleware bypass via path normalization (/_next/..)",
            "API route handler missing auth check",
            "Server actions callable without CSRF",
            "Source map exposure (.map files)",
        ],
        "first_moves": [
            "Request /_next/../api/admin — does path traversal bypass middleware?",
            "Check for .map files alongside JS bundles",
        ],
        "skills": ["hunt-nextjs"],
    },
    "remix": {
        "what_goes_wrong": [
            "Loader functions return data without auth check on nested routes",
            "Action functions miss CSRF validation on non-form submissions",
            "Route-based code splitting leaks admin route chunk names in manifest",
            "Server-side redirect in loader uses unvalidated user input for Location",
        ],
        "first_moves": [
            "Fetch route data directly via ?_data=routes/<route> loader API",
            "Check build manifest for all route chunk filenames",
            "Send X-Remix-Reload-Document: true to force full server render",
        ],
        "skills": ["hunt-auth-bypass", "hunt-api-misconfig"],
    },
    "spring": {
        "what_goes_wrong": [
            "Actuator endpoints exposed: /actuator/env, /actuator/heapdump",
            "SpEL injection in error handling",
            "Mass assignment via Spring data binding",
        ],
        "first_moves": [
            "Probe /actuator/* endpoints",
            "Try parameter binding: ?role=admin, ?class.module.classLoader...",
        ],
        "skills": ["hunt-springboot"],
    },
    "nodejs": {
        "what_goes_wrong": [
            "Prototype pollution via __proto__ or constructor.prototype",
            "NoSQL injection with MongoDB operators ($gt, $regex, $where)",
            "SSRF via URL parsing differences (node URL vs whatwg URL)",
        ],
        "first_moves": [
            "Send JSON with __proto__: {isAdmin: true}",
            "Send {\"password\": {\"$gt\": \"\"}} on login",
        ],
        "skills": ["hunt-nodejs", "hunt-prototype-pollution", "hunt-nosqli"],
    },
    "php": {
        "what_goes_wrong": [
            "Type juggling: '0e123' == '0e456' evaluates true",
            "Deserialization of untrusted data (unserialize)",
            "File include via LFI / path traversal",
            "Loose comparison in auth checks",
        ],
        "first_moves": [
            "Send 0 or '0e123' as password/token — type juggling in comparison?",
            "Try file=../../../etc/passwd in any file-related parameter",
        ],
        "skills": ["hunt-lfi", "hunt-deserialization"],
    },
    "oauth": {
        "what_goes_wrong": [
            "redirect_uri validation is prefix-only or allows subdirectory traversal",
            "State parameter not validated → CSRF on OAuth flow",
            "Token exchange grant allows cross-service privilege escalation",
            "Client credentials grant available to unauthorized clients",
        ],
        "first_moves": [
            "Modify redirect_uri: add @evil.com, add /callback/../evil, use different TLD",
            "Remove state parameter entirely — does the flow complete?",
            "Try client_credentials grant with guessed/leaked client_id",
        ],
        "skills": ["hunt-oauth"],
    },
    "okta": {
        "what_goes_wrong": [
            "Okta admin API exposed with default credentials or weak MFA",
            "SAML assertion manipulation allows role escalation",
            "User enumeration via login error differences",
            "Session token reuse across different Okta tenants",
        ],
        "first_moves": [
            "Check for exposed Okta admin console at /admin/",
            "Test SAML response manipulation (role, nameID)",
            "Compare login errors for existing vs non-existing users",
        ],
        "skills": ["okta-attack", "hunt-saml", "hunt-auth-bypass"],
    },
    "android": {
        "what_goes_wrong": [
            "Hardcoded API keys in APK manifest/resources",
            "Certificate pinning not enforced, allowing MITM",
            "Exported activities/receivers accessible without permission",
            "Insecure data storage in SharedPreferences or SQLite",
        ],
        "first_moves": [
            "Decompile APK, search for API keys and secrets",
            "Check AndroidManifest.xml for exported components",
            "Proxy traffic through Burp, check for cert pinning",
        ],
        "skills": ["apk-redteam-pipeline"],
    },
    "aws": {
        "what_goes_wrong": [
            "IMDS v1 accessible from SSRF → role credentials",
            "Overly permissive IAM policies allow escalation",
            "S3 bucket misconfiguration (public read/write/list)",
            "Lambda function environment variable secrets exposed",
        ],
        "first_moves": [
            "If SSRF exists: request http://169.254.169.254/latest/meta-data/iam/",
            "Check for public S3 buckets: s3.amazonaws.com/<bucket>",
            "Look for AWS region hints in headers/errors",
        ],
        "skills": ["cloud-iam-deep", "hunt-ssrf"],
    },
    "azure": {
        "what_goes_wrong": [
            "IMDS accessible at 169.254.169.254 with Metadata: true header",
            "Azure AD app registration allows dangerous permissions",
            "Blob storage public access misconfiguration",
        ],
        "first_moves": [
            "If SSRF: request IMDS with Metadata:true header",
            "Check for .blob.core.windows.net public containers",
        ],
        "skills": ["cloud-iam-deep"],
    },
    "gcp": {
        "what_goes_wrong": [
            "Metadata server at 169.254.169.254 leaks service account tokens",
            "Overly permissive Cloud IAM bindings",
            "Cloud Storage bucket ACL misconfiguration",
        ],
        "first_moves": [
            "If SSRF: request metadata.google.internal/computeMetadata/v1/",
            "Check for public GCS buckets: storage.googleapis.com/<bucket>",
        ],
        "skills": ["cloud-iam-deep"],
    },
    "solidity": {
        "what_goes_wrong": [
            "Reentrancy in external calls before state updates",
            "Integer overflow/underflow in token math",
            "Unprotected selfdestruct or delegatecall",
            "Front-running vulnerable transaction ordering",
        ],
        "first_moves": [
            "Review contract source for external calls before state changes",
            "Check for unchecked math operations",
            "Look for access control on privileged functions",
        ],
        "skills": ["web3-audit"],
    },
}


# ---------------------------------------------------------------------------
# Dynamic tech detection — derives tech signals from live response data
# ---------------------------------------------------------------------------

_HEADER_TECH_MAP = {
    "x-powered-by": {
        "express": "nodejs", "next.js": "nextjs", "php": "php",
        "asp.net": "dotnet", "django": "django",
    },
    "server": {
        "openresty": "nginx", "gunicorn": "django", "uvicorn": "django",
        "puma": "rails", "phusion passenger": "rails",
    },
    "x-runtime": {"": "rails"},
    "x-request-id": {},
}

_BODY_TECH_SIGNATURES = [
    (r"__remixContext|__remix|x-remix-", "remix"),
    (r"__NEXT_DATA__|_next/static|__nextjs", "nextjs"),
    (r"__NUXT__|nuxt\.config", "nuxtjs"),
    (r"graphql|__typename|__schema", "graphql"),
    (r"window\.shopify|shopify\.idToken|Shopify\.API", "shopify_app"),
    (r"csrf.token|authenticity_token|X-CSRF-Token", "csrf_double_submit"),
    (r"jwt|eyJ[A-Za-z0-9_-]{10,}\.", "jwt"),
    (r"ActionCable|cable\.js|/cable", "actioncable"),
    (r"swagger|openapi|api-docs", "swagger"),
    (r"wp-content|wp-json|wordpress", "wordpress"),
    (r"laravel_session|XSRF-TOKEN.*laravel", "laravel"),
    (r"csrfmiddlewaretoken|django", "django"),
    (r"\.amazonaws\.com|AWS|x-amz-", "aws"),
    (r"\.azure\.|\.windows\.net|x-ms-", "azure"),
    (r"\.googleapis\.com|gcp|x-goog-", "gcp"),
]


def detect_tech(headers=None, body="", url=""):
    """Derive technology signals from live HTTP response data.

    Returns a list of tech keys that match entries in TECH_PATTERNS.
    Call this during discovery/profiling, then pass results to
    build_hunt_guidance(signals, tech=detected_tech).
    """
    detected = set()
    headers = headers or {}
    hl = {k.lower(): v.lower() for k, v in headers.items()}

    for hdr, mapping in _HEADER_TECH_MAP.items():
        val = hl.get(hdr, "")
        if not val:
            continue
        if not mapping:
            detected.add(hdr.replace("-", ""))
            continue
        for sig, tech in mapping.items():
            if sig in val:
                detected.add(tech)
        if hdr == "x-runtime" and val:
            detected.add("rails")

    combined = (body + " " + url).lower()
    for pattern, tech in _BODY_TECH_SIGNATURES:
        if re.search(pattern, combined, re.I):
            detected.add(tech)

    return sorted(detected)


# ---------------------------------------------------------------------------
# Public API — called by testplan.py and engine.py
# ---------------------------------------------------------------------------

def patterns_for_signals(signals):
    """Return matching knowledge patterns for a set of signals.

    Checks all signal combinations, most specific first (more signals = better match).
    Returns list of pattern dicts, ordered by specificity.
    """
    if not signals:
        return []

    signal_set = set(signals)
    matches = []

    sorted_keys = sorted(SIGNAL_PATTERNS.keys(), key=lambda k: -len(k))

    for key_tuple in sorted_keys:
        if set(key_tuple).issubset(signal_set):
            entry = SIGNAL_PATTERNS[key_tuple]
            matches.append({
                "trigger": key_tuple,
                "what_goes_wrong": entry["what_goes_wrong"],
                "first_moves": entry["first_moves"],
                "evidence_bar": entry["evidence_bar"],
                "skills": entry.get("skills", []),
            })

    seen_single = set()
    deduped = []
    for m in matches:
        if len(m["trigger"]) == 1:
            sig = m["trigger"][0]
            if sig in seen_single:
                continue
            if any(sig in multi["trigger"] and len(multi["trigger"]) > 1 for multi in matches):
                seen_single.add(sig)
                continue
            seen_single.add(sig)
        deduped.append(m)

    return deduped


def patterns_for_tech(tech_list):
    """Return matching tech-specific patterns for detected technologies."""
    if not tech_list:
        return []

    matches = []
    seen = set()
    for t in tech_list:
        tl = re.sub(r'[^a-z0-9]', '', t.lower().strip())
        for tech_key, entry in TECH_PATTERNS.items():
            if tech_key in seen:
                continue
            tk = re.sub(r'[^a-z0-9]', '', tech_key)
            if tk in tl or tl in tk:
                seen.add(tech_key)
                matches.append({
                    "tech": tech_key,
                    "what_goes_wrong": entry["what_goes_wrong"],
                    "first_moves": entry["first_moves"],
                    "skills": entry.get("skills", []),
                })
    return matches


def build_hunt_guidance(signals, tech=None, method="GET"):
    """Build complete hunt guidance for one endpoint.

    Combines signal patterns, tech patterns, and universal checks into
    a single guidance block the hunt agent reads before testing.
    """
    guidance = {
        "signal_patterns": patterns_for_signals(signals),
        "tech_patterns": patterns_for_tech(tech or []),
        "universal_checks": [],
        "recommended_skills": [],
    }

    is_write = method in ("POST", "PUT", "PATCH", "DELETE")

    for uc in UNIVERSAL_CHECKS:
        if uc["name"] == "CSRF on state-changing" and not is_write:
            continue
        guidance["universal_checks"].append(uc)

    skill_set = set()
    for p in guidance["signal_patterns"]:
        skill_set.update(p.get("skills", []))
    for p in guidance["tech_patterns"]:
        skill_set.update(p.get("skills", []))
    for uc in guidance["universal_checks"]:
        if uc.get("skill"):
            skill_set.add(uc["skill"])

    guidance["recommended_skills"] = sorted(skill_set)
    return guidance


def format_guidance_text(guidance, max_patterns=3):
    """Format guidance into readable text for the hunt agent prompt."""
    lines = []

    for i, p in enumerate(guidance["signal_patterns"][:max_patterns]):
        trigger = " + ".join(p["trigger"])
        lines.append(f"PATTERN ({trigger}):")
        lines.append(f"  What goes wrong: {'; '.join(p['what_goes_wrong'][:3])}")
        lines.append(f"  First moves: {'; '.join(p['first_moves'][:3])}")
        lines.append(f"  Evidence bar: {p['evidence_bar']}")
        lines.append("")

    for tp in guidance["tech_patterns"][:2]:
        lines.append(f"TECH ({tp['tech']}):")
        lines.append(f"  Watch for: {'; '.join(tp['what_goes_wrong'][:2])}")
        lines.append(f"  Try: {'; '.join(tp['first_moves'][:2])}")
        lines.append("")

    if guidance["universal_checks"]:
        lines.append("ALSO CHECK:")
        for uc in guidance["universal_checks"][:3]:
            lines.append(f"  - {uc['name']}: {uc['check']}")
        lines.append("")

    if guidance["recommended_skills"]:
        lines.append(f"REFERENCE SKILLS: {', '.join(guidance['recommended_skills'])}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

def _selftest():
    # Signal matching — multi-key patterns suppress their single-key subsets
    m = patterns_for_signals(["handles_identity", "state_changing"])
    assert len(m) >= 1, f"expected >=1 patterns for identity+state: got {len(m)}"
    assert m[0]["trigger"] == ("handles_identity", "state_changing"), "most specific first"
    assert "hunt-idor" in m[0]["skills"]

    m2 = patterns_for_signals(["financial", "state_changing"])
    assert any("payment" in str(p["skills"]) for p in m2), "financial+state should suggest payment"

    m3 = patterns_for_signals(["auth_flow"])
    assert any("hunt-password-reset" in p["skills"] for p in m3)

    # Single-signal should still return when no multi covers it
    m4 = patterns_for_signals(["realtime"])
    assert len(m4) == 1, f"standalone signal should return 1 pattern: got {len(m4)}"

    # Tech matching
    tp = patterns_for_tech(["Next.js", "GraphQL"])
    tech_keys = {p["tech"] for p in tp}
    assert "nextjs" in tech_keys, f"missing nextjs: {tech_keys}"
    assert "graphql" in tech_keys, f"missing graphql: {tech_keys}"

    # Empty input
    assert patterns_for_signals([]) == []
    assert patterns_for_tech([]) == []

    # Full guidance
    g = build_hunt_guidance(["handles_identity", "financial", "state_changing"],
                           tech=["Rails", "GraphQL"], method="POST")
    assert g["signal_patterns"], "should have signal patterns"
    assert g["tech_patterns"], "should have tech patterns"
    assert g["recommended_skills"], "should have skills"
    assert g["universal_checks"], "should have universal checks"

    # Text formatting
    text = format_guidance_text(g)
    assert "PATTERN" in text
    assert "TECH" in text
    assert "REFERENCE SKILLS" in text
    assert len(text) > 100

    # Dynamic tech detection
    dt = detect_tech(
        headers={"X-Runtime": "0.012", "Server": "nginx"},
        body='<script>window.__remixContext = {}</script>',
    )
    assert "rails" in dt, f"should detect rails from X-Runtime, got {dt}"
    assert "remix" in dt, f"should detect remix from body, got {dt}"
    dt2 = detect_tech(body='{"data":{"__typename":"Query"}}')
    assert "graphql" in dt2, f"should detect graphql from __typename, got {dt2}"
    assert detect_tech() == [], "empty input should return empty"

    print("knowledge.py: selftest PASSED")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _selftest()
    else:
        import json
        signals = sys.argv[1:] if len(sys.argv) > 1 else ["handles_identity", "state_changing"]
        g = build_hunt_guidance(signals)
        print(json.dumps(g, indent=2))
