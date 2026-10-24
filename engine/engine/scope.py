#!/usr/bin/env python3
"""
scope.py — deterministic scope safety for the engagement engine.

The engine may run unattended, so scope is enforced in CODE, not by trusting an
LLM. Every host/URL is checked here before any agent is allowed to touch it.
Deny wins: an out-of-scope match excludes even if an in-scope pattern also matches.
Default deny: anything not matching an in-scope pattern is out of scope.

Pattern forms (matched against the URL's host):
  example.com        -> the apex AND any subdomain (example.com, api.example.com)
  *.example.com      -> any subdomain (NOT the bare apex)
  api.example.com    -> that exact host
  10.0.0.0/8         -> any IP in the CIDR (IPv4)
  re:^staging[0-9]+\\.example\\.com$   -> explicit regex (prefix re:)
"""
import ipaddress
import re
from urllib.parse import urlparse


def _host_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    host = (urlparse(t).hostname or "").lower().rstrip(".")
    return host


def _match(pattern, host):
    p = pattern.strip().lower()
    if not p or not host:
        return False
    if p.startswith("="):
        return host == p[1:]
    if p.startswith("re:"):
        try:
            return re.search(p[3:], host) is not None
        except re.error:
            return False
    if "/" in p and p.replace(".", "").replace("/", "").isdigit():  # CIDR
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    if p.startswith("*."):
        base = p[2:]
        return host.endswith("." + base)
    # bare domain: apex or any subdomain; or exact host
    return host == p or host.endswith("." + p)


class Scope:
    def __init__(self, in_scope, out_of_scope=None, seeds=None, name="engagement",
                 user_agent="", endpoints=None, roe_extra="", skip_param_mining=False,
                 proxy="", impersonate="", path_restrictions=None,
                 out_path_restrictions=None):
        self.in_scope = [p for p in (in_scope or []) if p.strip()]
        self.out_of_scope = [p for p in (out_of_scope or []) if p.strip()]
        self.seeds = seeds or []
        self.name = name
        self.user_agent = user_agent or ""          # per-target UA (e.g. a SOC-whitelist tag)
        self.endpoints = endpoints or []            # documented API routes for path-scoped programs
        self.roe_extra = roe_extra or ""            # extra rules-of-engagement text (program-specific)
        self.skip_param_mining = bool(skip_param_mining)  # True => no gau/katana crawl (scanner-forbidden)
        self.proxy = proxy or ""                    # egress proxy for edge-gated hosts (IP/geo filtered)
        self.impersonate = impersonate or ""        # curl_cffi TLS profile (e.g. safari_ios) via netget
        self.path_restrictions = path_restrictions or {}  # {host: ["/allowed/path"]} from URL-scoped entries
        self.out_path_restrictions = out_path_restrictions or {}  # {host: ["/excluded/path"]} path-specific exclusions
        self.policy = {}  # program-level policy: rate_limit, prohibited_actions, required_headers, auth_restrictions

    @classmethod
    def load(cls, path):
        import json
        d = json.load(open(path))
        s = cls(d.get("in_scope", []), d.get("out_of_scope", []),
                d.get("seeds", []), d.get("name", "engagement"),
                user_agent=d.get("user_agent", ""), endpoints=d.get("endpoints", []),
                roe_extra=d.get("roe_extra", ""), skip_param_mining=d.get("skip_param_mining", False),
                proxy=d.get("proxy", ""), impersonate=d.get("impersonate", ""),
                path_restrictions=d.get("path_restrictions", {}),
                out_path_restrictions=d.get("out_path_restrictions", {}))
        s.policy = {
            "rate_limit": d.get("rate_limit"),
            "prohibited_actions": d.get("prohibited_actions", []),
            "required_headers": d.get("required_headers", {}),
            "auth_restrictions": d.get("auth_restrictions"),
        }
        return s

    def _path_prefixes_for(self, host):
        """Resolve path restrictions for a host, checking both exact and wildcard keys."""
        if not self.path_restrictions:
            return None
        # Exact host match first
        prefixes = self.path_restrictions.get(host)
        if prefixes:
            return prefixes
        # Check wildcard keys: *.example.com should apply to api.example.com
        for key, pfxs in self.path_restrictions.items():
            if key.startswith("*.") and host.endswith("." + key[2:]):
                return pfxs
        return None

    def _out_path_prefixes_for(self, host):
        """Resolve path-specific exclusions for a host."""
        if not self.out_path_restrictions:
            return None
        prefixes = self.out_path_restrictions.get(host)
        if prefixes:
            return prefixes
        for key, pfxs in self.out_path_restrictions.items():
            if key.startswith("*.") and host.endswith("." + key[2:]):
                return pfxs
        return None

    @staticmethod
    def _path_allowed(path, prefixes):
        return any(
            path == pfx or path.startswith(pfx + "/") or (pfx.endswith("/") and path.startswith(pfx))
            for pfx in prefixes
        )

    def in_scope_host(self, target):
        host = _host_of(target)
        if not host:
            return False
        if any(_match(p, host) for p in self.out_of_scope):
            return False          # deny wins
        if not any(_match(p, host) for p in self.in_scope):
            return False
        try:
            path = urlparse(target).path or "/"
        except Exception:
            path = "/"
        prefixes = self._path_prefixes_for(host)
        if prefixes and not self._path_allowed(path, prefixes):
            return False
        out_pfx = self._out_path_prefixes_for(host)
        if out_pfx and self._path_allowed(path, out_pfx):
            return False
        return True

    def reject_reason(self, target):
        """Return None if in scope, else a human reason (for logging)."""
        host = _host_of(target)
        if not host:
            return "could not parse host"
        if any(_match(p, host) for p in self.out_of_scope):
            return f"{host} matches an out-of-scope rule"
        if not any(_match(p, host) for p in self.in_scope):
            return f"{host} matches no in-scope rule (default deny)"
        try:
            path = urlparse(target).path or "/"
        except Exception:
            path = "/"
        prefixes = self._path_prefixes_for(host)
        if prefixes and not self._path_allowed(path, prefixes):
            return f"{path} outside allowed path(s) for {host}: {prefixes}"
        out_pfx = self._out_path_prefixes_for(host)
        if out_pfx and self._path_allowed(path, out_pfx):
            return f"{path} matches excluded path(s) for {host}: {out_pfx}"
        return None


def _selftest():
    s = Scope(in_scope=["example.com", "*.test.example.com", "10.0.0.0/8",
                        "re:^lab[0-9]+\\.acme\\.io$"],
              out_of_scope=["admin.example.com", "internal.example.com"])
    ok = lambda t: s.in_scope_host(t)
    assert ok("https://example.com/login")           # apex
    assert ok("http://api.example.com/x")            # subdomain of bare domain
    assert ok("https://a.test.example.com")          # wildcard
    assert ok("https://10.1.2.3:8080/")              # CIDR
    assert ok("https://lab42.acme.io")               # regex
    assert not ok("https://admin.example.com")       # out-of-scope (deny wins)
    assert not ok("https://internal.example.com/x")  # out-of-scope
    assert ok("https://test.example.com")            # in scope via bare example.com rule
    assert not ok("https://evil.com")                # default deny
    assert not ok("https://notexample.com")          # suffix-confusion guard
    assert not ok("https://example.com.evil.com")    # suffix-confusion guard
    assert not ok("https://11.0.0.1")                # outside CIDR
    assert s.reject_reason("https://evil.com")
    assert s.reject_reason("https://example.com") is None
    # wildcard depth: *.test.example.com needs a label deeper than test.example.com
    s2 = Scope(in_scope=["*.test.example.com"])
    assert s2.in_scope_host("a.test.example.com")
    assert not s2.in_scope_host("test.example.com")
    # S02: wildcard path restrictions apply to resolved subdomains
    s3 = Scope(in_scope=["*.example.com"],
               path_restrictions={"*.example.com": ["/api/research"]})
    assert s3.in_scope_host("https://api.example.com/api/research/papers")
    assert not s3.in_scope_host("https://api.example.com/admin/users")
    assert not s3.in_scope_host("https://api.example.com/")
    # out_path_restrictions: path-specific exclusions
    s5 = Scope(in_scope=["*.acme.com"], out_of_scope=[],
               out_path_restrictions={"*.acme.com": ["/admin"]})
    assert s5.in_scope_host("https://api.acme.com/api/v1/users")   # allowed
    assert not s5.in_scope_host("https://api.acme.com/admin/users") # excluded by path
    assert s5.in_scope_host("https://api.acme.com/")               # allowed
    assert s5.reject_reason("https://api.acme.com/admin/panel")     # has reason
    assert s5.reject_reason("https://api.acme.com/api/v1") is None  # no reason
    # S03: exact-host mode with = prefix
    s4 = Scope(in_scope=["=api.example.com"])
    assert s4.in_scope_host("https://api.example.com/x")
    assert not s4.in_scope_host("https://sub.api.example.com")
    assert not s4.in_scope_host("https://example.com")
    print("scope.py self-test: PASS")


if __name__ == "__main__":
    _selftest()
