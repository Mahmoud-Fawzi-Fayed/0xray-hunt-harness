#!/usr/bin/env python3
"""
egress.py — transport-level egress policy broker for the hunt harness.

Single decision point for ALL outbound network requests. Default-deny.
Wraps scope.py policy and adds:
  - Prohibited HTTP method enforcement
  - Required header injection (SOC tag, custom UA)
  - OSINT/research traffic allowlist (separate from target testing)
  - Per-decision audit trail
  - Fail-closed on broker unavailability

Every harness transport (netget.py, browser.py, subprocess) must check
egress policy before sending any packet.

CLI:
  python3 egress.py selftest
  python3 egress.py check <METHOD> <URL>     # one-shot egress decision
"""
import json
import os
import re
import sys
import threading
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

# OSINT destinations allowed without target scope (read-only research).
# Kept minimal — only well-known search/docs sites.
_OSINT_HOSTS = frozenset({
    "www.google.com", "google.com",
    "www.bing.com", "bing.com",
    "duckduckgo.com", "www.duckduckgo.com",
    "web.archive.org",
    "crt.sh",
    "raw.githubusercontent.com", "github.com", "api.github.com",
    "developer.mozilla.org",
})

# Methods that are always allowed for OSINT (read-only)
_OSINT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Localhost addresses (always allowed — selftest, local dev)
_LOCALHOST = frozenset({"localhost", "127.0.0.1", "::1"})

_LOG_LOCK = threading.Lock()


class EgressDecision:
    __slots__ = ("allowed", "reason", "policy_source")

    def __init__(self, allowed, reason, policy_source="egress"):
        self.allowed = allowed
        self.reason = reason
        self.policy_source = policy_source

    def __bool__(self):
        return self.allowed

    def __repr__(self):
        tag = "ALLOW" if self.allowed else "DENY"
        return f"EgressDecision({tag}: {self.reason})"


class EgressPolicy:
    """Transport-level egress policy broker. Default-deny."""

    _STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, scope=None, osint_allowed=True, audit_path=None, allow_intrusive=False):
        self._scope = scope
        self._osint_allowed = osint_allowed
        self._audit_path = audit_path
        self._allow_intrusive = allow_intrusive
        self._prohibited_methods = set()
        self._required_headers = {}
        if scope and hasattr(scope, "policy"):
            pol = scope.policy or {}
            for m in (pol.get("prohibited_actions") or []):
                self._prohibited_methods.add(m.upper())
            self._required_headers = dict(pol.get("required_headers") or {})

    @classmethod
    def from_scope_file(cls, path, **kwargs):
        from scope import Scope
        sc = Scope.load(path)
        return cls(scope=sc, **kwargs)

    def check_egress(self, method, url, headers=None):
        """Single decision point. Returns EgressDecision."""
        method = (method or "GET").upper()
        host = self._host_of(url)

        if not host:
            return self._deny("could not parse host from URL")

        # Localhost always allowed (selftest, local dev)
        if host in _LOCALHOST or host.startswith("127."):
            return self._allow("localhost")

        # Prohibited method check (applies to ALL destinations)
        if method in self._prohibited_methods:
            return self._deny(f"method {method} prohibited by engagement policy")

        # Scope-based decision (target traffic)
        if self._scope:
            reason = self._scope.reject_reason(url)
            if reason is None:
                # In-scope: enforce non-intrusive mode (block state-changing methods unless intrusive allowed)
                if (not self._allow_intrusive
                        and method in self._STATE_CHANGING_METHODS):
                    return self._deny(f"state-changing method {method} blocked (non-intrusive mode)")
                return self._allow(f"in-scope target ({host})")
            # Not in target scope — check OSINT allowlist
            if self._osint_allowed and self._is_osint(method, host):
                return self._allow(f"OSINT research ({host})")
            return self._deny(f"scope: {reason}")

        # No scope loaded — fail closed
        return self._deny("no scope policy loaded (fail-closed)")

    def inject_required_headers(self, headers):
        """Return headers dict with required headers merged in. Does not overwrite existing."""
        if not self._required_headers:
            return headers or {}
        out = dict(headers or {})
        for k, v in self._required_headers.items():
            out.setdefault(k, v)
        # Also inject SOC tag UA from environment
        ua = os.environ.get("HUNT_USER_AGENT")
        if ua:
            out.setdefault("User-Agent", ua)
        return out

    def record_decision(self, method, url, decision):
        """Append an egress decision to the audit log."""
        if not self._audit_path:
            return
        entry = {
            "ts": time.time(),
            "method": method,
            "url": (url or "")[:500],
            "allowed": decision.allowed,
            "reason": decision.reason,
            "source": decision.policy_source,
        }
        try:
            with _LOG_LOCK:
                os.makedirs(os.path.dirname(self._audit_path), exist_ok=True)
                with open(self._audit_path, "a") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    def _allow(self, reason):
        return EgressDecision(True, reason)

    def _deny(self, reason):
        return EgressDecision(False, reason)

    @staticmethod
    def _host_of(url):
        try:
            from urllib.parse import urlparse
            t = str(url or "").strip()
            if "://" not in t:
                t = "//" + t
            return (urlparse(t).hostname or "").lower().rstrip(".")
        except Exception:
            return ""

    @staticmethod
    def _is_osint(method, host):
        if method not in _OSINT_METHODS:
            return False
        if host in _OSINT_HOSTS:
            return True
        # Allow subdomains of known OSINT hosts
        for oh in _OSINT_HOSTS:
            if host.endswith("." + oh):
                return True
        return False


# --- Module-level singleton (set by engine init, used by netget.py) ---
_EGRESS_POLICY = None
_EGRESS_LOCK = threading.Lock()


def set_egress_policy(policy):
    global _EGRESS_POLICY
    with _EGRESS_LOCK:
        _EGRESS_POLICY = policy


def get_egress_policy():
    with _EGRESS_LOCK:
        return _EGRESS_POLICY


def check(method, url, headers=None):
    """Module-level convenience: check egress using the active policy."""
    pol = get_egress_policy()
    if pol is None:
        host = EgressPolicy._host_of(url)
        if host in _LOCALHOST or (host and host.startswith("127.")):
            return EgressDecision(True, "localhost (no policy needed)")
        return EgressDecision(False, "no egress policy loaded (fail-closed)")
    decision = pol.check_egress(method, url, headers)
    pol.record_decision(method, url, decision)
    return decision


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv or argv[0] in ("--help", "-h"):
        print("usage: egress.py selftest | check <METHOD> <URL>", file=sys.stderr)
        return 0
    if argv[0] == "selftest":
        return _selftest()
    if argv[0] == "check" and len(argv) >= 3:
        method, url = argv[1], argv[2]
        pol = get_egress_policy()
        if pol is None:
            sf = os.environ.get("HUNT_SCOPE_FILE")
            if sf and os.path.isfile(sf):
                pol = EgressPolicy.from_scope_file(sf)
            else:
                print("ERROR: no egress policy — set HUNT_SCOPE_FILE or call set_egress_policy()", file=sys.stderr)
                return 1
        d = pol.check_egress(method, url)
        print(f"{'ALLOW' if d.allowed else 'DENY'}: {d.reason}")
        return 0 if d.allowed else 1
    print(f"unknown command: {argv[0]}", file=sys.stderr)
    return 1


def _selftest():
    import tempfile
    from scope import Scope

    # --- Basic scope-based decisions ---
    sc = Scope(["*.example.com"], ["admin.example.com"], name="egress-test")
    pol = EgressPolicy(scope=sc)

    # In-scope allowed
    d = pol.check_egress("GET", "https://api.example.com/users")
    assert d.allowed, f"expected allow: {d}"

    # Out-of-scope denied
    d = pol.check_egress("GET", "https://evil.com/steal")
    assert not d.allowed, f"expected deny: {d}"

    # OOS by out_of_scope rule
    d = pol.check_egress("GET", "https://admin.example.com/panel")
    assert not d.allowed, f"expected deny for OOS: {d}"

    # --- Localhost always allowed ---
    d = pol.check_egress("POST", "http://127.0.0.1:8080/test")
    assert d.allowed, f"localhost should be allowed: {d}"
    d = pol.check_egress("DELETE", "http://localhost:3000/api")
    assert d.allowed, f"localhost should be allowed: {d}"

    # --- OSINT allowlist ---
    d = pol.check_egress("GET", "https://crt.sh/?q=example.com")
    assert d.allowed, f"OSINT GET should be allowed: {d}"
    d = pol.check_egress("POST", "https://crt.sh/submit")
    assert not d.allowed, f"OSINT POST should be denied: {d}"
    d = pol.check_egress("GET", "https://github.com/repo")
    assert d.allowed, f"OSINT github should be allowed: {d}"

    # --- OSINT disabled ---
    pol_no_osint = EgressPolicy(scope=sc, osint_allowed=False)
    d = pol_no_osint.check_egress("GET", "https://crt.sh/?q=example.com")
    assert not d.allowed, f"OSINT should be denied when disabled: {d}"

    # --- Prohibited methods ---
    sc2 = Scope(["*.target.io"], name="method-test")
    sc2.policy = {"prohibited_actions": ["DELETE", "PATCH"], "required_headers": {}}
    pol2 = EgressPolicy(scope=sc2, allow_intrusive=True)
    d = pol2.check_egress("GET", "https://api.target.io/users")
    assert d.allowed, f"GET should be allowed: {d}"
    d = pol2.check_egress("DELETE", "https://api.target.io/users/1")
    assert not d.allowed, f"DELETE should be prohibited: {d}"
    d = pol2.check_egress("PATCH", "https://api.target.io/users/1")
    assert not d.allowed, f"PATCH should be prohibited: {d}"
    d = pol2.check_egress("POST", "https://api.target.io/users")
    assert d.allowed, f"POST should be allowed: {d}"

    # --- Required headers injection ---
    sc3 = Scope(["target.com"], name="header-test")
    sc3.policy = {"required_headers": {"X-Bug-Bounty": "0xRay-H1"}, "prohibited_actions": []}
    pol3 = EgressPolicy(scope=sc3)
    h = pol3.inject_required_headers({"Content-Type": "application/json"})
    assert h.get("X-Bug-Bounty") == "0xRay-H1", f"required header missing: {h}"
    assert h.get("Content-Type") == "application/json", f"existing header lost: {h}"
    # Don't overwrite existing
    h2 = pol3.inject_required_headers({"X-Bug-Bounty": "custom"})
    assert h2["X-Bug-Bounty"] == "custom", f"should not overwrite: {h2}"

    # --- Fail-closed: no scope ---
    pol_empty = EgressPolicy(scope=None)
    d = pol_empty.check_egress("GET", "https://anything.com/")
    assert not d.allowed, f"no scope = fail closed: {d}"
    # But localhost still works
    d = pol_empty.check_egress("GET", "http://127.0.0.1:8080/")
    assert d.allowed, f"localhost without scope: {d}"

    # --- Audit trail ---
    td = tempfile.mkdtemp()
    audit_path = os.path.join(td, "egress-audit.jsonl")
    pol_audit = EgressPolicy(scope=sc, audit_path=audit_path)
    d = pol_audit.check_egress("GET", "https://api.example.com/")
    pol_audit.record_decision("GET", "https://api.example.com/", d)
    d2 = pol_audit.check_egress("GET", "https://evil.com/")
    pol_audit.record_decision("GET", "https://evil.com/", d2)
    with open(audit_path) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == 2, f"expected 2 audit entries: {len(lines)}"
    assert lines[0]["allowed"] is True
    assert lines[1]["allowed"] is False

    # --- Module-level singleton ---
    set_egress_policy(pol)
    d = check("GET", "https://api.example.com/test")
    assert d.allowed, f"module-level check should work: {d}"
    d = check("GET", "https://evil.com/steal")
    assert not d.allowed, f"module-level deny should work: {d}"
    set_egress_policy(None)
    d = check("GET", "https://anything.com/")
    assert not d.allowed, f"no policy = fail closed: {d}"
    d = check("GET", "http://127.0.0.1:8080/")
    assert d.allowed, f"localhost without policy: {d}"

    # --- Port enforcement (via scope) ---
    sc_port = Scope(["*.example.com:8443"])
    pol_port = EgressPolicy(scope=sc_port)
    d = pol_port.check_egress("GET", "https://api.example.com:8443/")
    assert d.allowed, f"correct port should be allowed: {d}"
    d = pol_port.check_egress("GET", "https://api.example.com:443/")
    assert not d.allowed, f"wrong port should be denied: {d}"

    # --- Non-intrusive mode: state-changing methods blocked on target scope ---
    sc_ni = Scope(["*.example.com"], name="non-intrusive-test")
    pol_ni = EgressPolicy(scope=sc_ni, allow_intrusive=False)
    d = pol_ni.check_egress("GET", "https://api.example.com/users")
    assert d.allowed, f"GET should be allowed in non-intrusive: {d}"
    d = pol_ni.check_egress("HEAD", "https://api.example.com/users")
    assert d.allowed, f"HEAD should be allowed in non-intrusive: {d}"
    d = pol_ni.check_egress("OPTIONS", "https://api.example.com/users")
    assert d.allowed, f"OPTIONS should be allowed in non-intrusive: {d}"
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        d = pol_ni.check_egress(m, "https://api.example.com/users")
        assert not d.allowed, f"{m} should be blocked in non-intrusive: {d}"
        assert "non-intrusive" in d.reason, f"reason should mention non-intrusive: {d.reason}"
    # Localhost exempt from non-intrusive
    d = pol_ni.check_egress("POST", "http://127.0.0.1:8080/test")
    assert d.allowed, f"localhost POST allowed even in non-intrusive: {d}"
    # OSINT POST still blocked (it's OOS + non-GET)
    d = pol_ni.check_egress("POST", "https://crt.sh/submit")
    assert not d.allowed, f"OSINT POST should still be denied: {d}"

    # --- Intrusive mode: state-changing methods allowed ---
    pol_intr = EgressPolicy(scope=sc_ni, allow_intrusive=True)
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        d = pol_intr.check_egress(m, "https://api.example.com/users")
        assert d.allowed, f"{m} should be allowed in intrusive mode: {d}"

    print("egress.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
