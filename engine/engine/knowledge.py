#!/usr/bin/env python3
"""Evidence-based technology fingerprinting for parser selection.

Hunting guidance does not come from this module. Function profiles and live
hypotheses drive tests; vulnerability references are selected later by skill_map.
"""
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(os.path.dirname(ENGINE), "skills")

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
    """Return technologies explicitly evidenced by response headers, body, or URL."""
    detected = set()
    headers = headers or {}
    normalized = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    for header, mapping in _HEADER_TECH_MAP.items():
        value = normalized.get(header, "")
        if not value:
            continue
        if not mapping:
            detected.add(header.replace("-", ""))
            continue
        for signature, tech in mapping.items():
            if signature in value:
                detected.add(tech)
        if header == "x-runtime" and value:
            detected.add("rails")
    combined = (str(body or "") + " " + str(url or "")).lower()
    for pattern, tech in _BODY_TECH_SIGNATURES:
        if re.search(pattern, combined, re.I):
            detected.add(tech)
    return sorted(detected)


def build_hunt_guidance(signals=None, tech=None, method="GET"):
    """Compatibility result: no pre-hypothesis vulnerability guidance is injected."""
    return {"signal_patterns": [], "tech_patterns": [], "universal_checks": [], "recommended_skills": []}


def format_guidance_text(guidance, max_patterns=3):
    if not guidance:
        return ""
    lines = []
    if guidance.get("recommended_skills"):
        lines.append("REFERENCE SKILLS: " + ", ".join(guidance["recommended_skills"]))
    return "\n".join(lines)


def _selftest():
    guidance = build_hunt_guidance(["anything"], tech=["Anything"], method="POST")
    assert not guidance["signal_patterns"] and not guidance["tech_patterns"], guidance
    assert not guidance["recommended_skills"] and format_guidance_text(guidance) == ""
    detected = detect_tech(headers={"X-Runtime": "0.012", "Server": "nginx"},
                           body='<script>window.__remixContext = {}</script>')
    assert "rails" in detected and "remix" in detected, detected
    assert "graphql" in detect_tech(body='{"data":{"__typename":"Query"}}')
    assert detect_tech() == []
    print("knowledge.py: selftest PASSED")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _selftest()
    else:
        import json
        print(json.dumps(build_hunt_guidance(sys.argv[1:]), indent=2))
