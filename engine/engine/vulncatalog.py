"""Canonical vulnerability names shared by planning, skills, dedup, validation, and coverage."""
import re

ALIASES = {
    "mfa": "2fa-bypass", "mfa-bypass": "2fa-bypass", "2fa": "2fa-bypass",
    "dom": "dom-xss", "dom-based-xss": "dom-xss",
    "subdomain": "subdomain-takeover", "subdomain-takeover": "subdomain-takeover",
    "secret": "info-leak", "secret-leak": "info-leak",
    "sensitive-data-exposure": "info-leak", "information-disclosure": "info-leak",
    "mass_assignment": "mass-assignment", "privesc": "privilege-escalation",
    "bola": "idor", "bfla": "idor", "broken-access-control": "idor",
    "broken-object-level-authorization": "idor", "access-control": "idor",
    "authorization": "idor", "bac": "idor",
    "toctou": "race-condition", "request-smuggling": "http-smuggling",
    "cache-deception": "cache-poison", "web-cache-poisoning": "cache-poison",
    "payment-logic": "payment-logic", "jwt-manipulation": "jwt",
    "command-injection": "rce", "os-command-injection": "rce",
    "path-traversal": "lfi", "directory-traversal": "lfi", "rfi": "lfi",
    "prototype_pollution": "prototype-pollution", "open_redirect": "open-redirect",
    "sql-injection": "sqli", "nosql-injection": "nosqli",
    "cross-site-scripting": "xss", "stored-xss": "xss", "reflected-xss": "xss",
    "authentication-bypass": "auth-bypass", "oauth-misconfiguration": "oauth",
    "prompt-injection": "llm-ai", "ai": "llm-ai",
}

SKILLS = {
    "dom-xss": "hunt-dom", "subdomain-takeover": "hunt-subdomain",
    "info-leak": "hunt-source-leak", "2fa-bypass": "hunt-2fa-bypass",
    "privilege-escalation": "hunt-auth-bypass",
}

METHODOLOGY = {
    "discovery", "dispatch", "hypothesis", "methodology", "misc", "waf-bypass",
    "api-fuzzing", "api-owasp",
}


def canonical_class(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return ALIASES.get(slug, ALIASES.get(text, slug))


def skill_name(value):
    cls = canonical_class(value)
    return SKILLS.get(cls, "hunt-" + cls) if cls else "hunt-hypothesis"


def is_methodology(value):
    return canonical_class(value) in METHODOLOGY


def is_vulnerability(value):
    return bool(canonical_class(value)) and not is_methodology(value)
