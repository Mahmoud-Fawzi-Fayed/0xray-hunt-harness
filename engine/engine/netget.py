#!/usr/bin/env python3
"""
netget.py — one HTTP client for edge-gated targets: curl_cffi TLS impersonation + an optional egress
proxy + the program's mandatory User-Agent.

Some targets (e.g. a mobile API backend behind a WAF) reset plain curl/requests by source IP or TLS
fingerprint. This routes requests through the configured proxy with a real browser/iOS TLS fingerprint
so recon and the hunt agent can reach an AUTHORIZED, in-scope host.

Config (the engine sets these from the target scope — proxy/impersonate/user_agent):
  HUNT_USER_AGENT   required UA (SOC tag)
  HUNT_IMPERSONATE  curl_cffi profile (default: safari_ios)
  HUNT_PROXY        http(s)/socks5 proxy URL for egress (optional)

CLI — what the hunt agent uses INSTEAD of curl for a gated target:
  python3 netget.py GET  "https://host/path"
  python3 netget.py POST "https://host/path" '{"k":"v"}'      # body as last arg (JSON auto-detected)
"""
import json
import os
import sys


def _cfg():
    return (os.environ.get("HUNT_USER_AGENT") or "",
            os.environ.get("HUNT_IMPERSONATE") or "safari_ios",
            os.environ.get("HUNT_PROXY") or "")


def get(url, method="GET", data=None, headers=None, timeout=25):
    """Return (status_code:int, text:str, headers:dict). status 0 on transport error (see headers['_error'])."""
    ua, imp, proxy = _cfg()
    h = dict(headers or {})
    if ua:
        h.setdefault("User-Agent", ua)
    try:
        from curl_cffi import requests as cr
    except Exception as e:  # noqa: BLE001
        return 0, "", {"_error": f"curl_cffi unavailable: {e}"}
    kw = {"impersonate": imp, "timeout": timeout, "headers": h, "verify": True}
    if proxy:
        kw["proxies"] = {"http": proxy, "https": proxy}
    try:
        r = cr.request(method.upper(), url, data=data, **kw)
        return r.status_code, r.text, {k.lower(): v for k, v in r.headers.items()}
    except Exception as e:  # noqa: BLE001
        return 0, "", {"_error": str(e)}


def _main(argv):
    if not argv:
        print("usage: netget.py <METHOD> <URL> [body]", file=sys.stderr)
        return 2
    if len(argv) == 1:
        method, url, body = "GET", argv[0], None
    else:
        method, url, body = argv[0], argv[1], (argv[2] if len(argv) > 2 else None)
    hdrs = {}
    if body:
        try:
            json.loads(body)
            hdrs["Content-Type"] = "application/json"
        except ValueError:
            pass
    code, text, h = get(url, method=method, data=body, headers=hdrs)
    err = h.get("_error")
    print(f"HTTP {code}" + (f"  [transport error: {err}]" if err else ""))
    for k in ("server", "content-type", "content-length", "www-authenticate", "location", "set-cookie"):
        if h.get(k):
            print(f"{k}: {h[k]}")
    print("---")
    print((text or "")[:4000])
    return 0 if code else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
