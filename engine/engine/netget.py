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
import time
import threading

# --- Adaptive rate limiter (per-host) ---
_RL_LOCK = threading.Lock()
_RL_STATE = {}  # host -> {"backoff": float, "consecutive_blocks": int, "last_req": float}
_RL_MAX_BACKOFF = 30.0
_RL_BLOCK_PAUSE = 300  # 5 min pause after 5 consecutive 403s
_RL_MIN_DELAY = 1.0 / max(0.1, float(os.environ.get("HUNT_REQUESTS_PER_SECOND", "10") or 10))

# Defense-in-depth scope guard — set by engine init via set_scope_guard()
_SCOPE_GUARD = None  # Scope instance or None (disabled)

# Connection pooling — reuse TCP connections across requests
_RQ_SESSION = None
_RQ_LOCK = threading.Lock()


def _get_session():
    global _RQ_SESSION
    if _RQ_SESSION is None:
        with _RQ_LOCK:
            if _RQ_SESSION is None:
                import requests as rq
                _RQ_SESSION = rq.Session()
    return _RQ_SESSION


def set_scope_guard(scope):
    """Set the module-level scope guard. Called by engine at init."""
    global _SCOPE_GUARD
    _SCOPE_GUARD = scope


class ScopeViolation(Exception):
    """Raised when a request targets an out-of-scope host."""


def _rate_limit(host, status):
    """Update per-host rate state after a response."""
    with _RL_LOCK:
        st = _RL_STATE.setdefault(host, {"backoff": 0.0, "consecutive_blocks": 0, "last_req": 0})
        if status == 429:
            st["backoff"] = min(st["backoff"] * 2 or 1.0, _RL_MAX_BACKOFF)
        elif status == 403:
            st["consecutive_blocks"] += 1
            if st["consecutive_blocks"] >= 5:
                st["backoff"] = _RL_BLOCK_PAUSE
        else:
            st["backoff"] = 0.0
            st["consecutive_blocks"] = 0
        st["last_req"] = time.time()


def _wait_for_host(host):
    """Sleep if the host is rate-limited or min inter-request delay not met."""
    with _RL_LOCK:
        st = _RL_STATE.get(host)
        if not st:
            return
        elapsed = time.time() - st["last_req"]
        delay = st["backoff"] if st["backoff"] > 0 else _RL_MIN_DELAY
        wait = max(0, delay - elapsed)
        if wait > 0:
            time.sleep(min(wait, _RL_MAX_BACKOFF))


def _burp_proxy_if_available():
    try:
        from burp import is_burp_available, BURP_PROXY
        if is_burp_available():
            return BURP_PROXY
    except ImportError:
        pass
    return ""


def _cfg():
    proxy = os.environ.get("HUNT_PROXY") or _burp_proxy_if_available()
    return (os.environ.get("HUNT_USER_AGENT") or "",
            os.environ.get("HUNT_IMPERSONATE") or "safari_ios",
            proxy,
            os.environ.get("HUNT_PROXY_LIST") or "")


def _pick_proxy(proxy, proxy_list):
    """Round-robin proxy from HUNT_PROXY_LIST file, or single HUNT_PROXY."""
    if proxy_list and os.path.isfile(proxy_list):
        try:
            with open(proxy_list) as f:
                proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if proxies:
                _pick_proxy._i = getattr(_pick_proxy, "_i", -1) + 1
                return proxies[_pick_proxy._i % len(proxies)]
        except OSError:
            pass
    return proxy


_DEFAULT_TIMEOUT = int(os.environ.get("HUNT_REQUEST_TIMEOUT", "30") or 30)


def get(url, method="GET", data=None, headers=None, timeout=None, ident=None, slug=None, allow_redirects=False,
        _bypass_scope=False):
    """Return (status_code:int, text:str, headers:dict). status 0 on transport error (see headers['_error']).
    ident 'A'/'B' loads that stored session (cookie/bearer/headers) for authenticated + cross-account tests."""
    if timeout is None:
        timeout = _DEFAULT_TIMEOUT
    if _SCOPE_GUARD and not _bypass_scope:
        reason = _SCOPE_GUARD.reject_reason(url)
        if reason:
            return 0, "", {"_error": f"scope violation: {reason}"}
    ua, imp, proxy, proxy_list = _cfg()
    h = dict(headers or {})
    if ua:
        h.setdefault("User-Agent", ua)
    if ident:
        try:
            import authn
            af = os.environ.get("HUNT_AUTH_FILE")
            sslug = slug or os.environ.get("HUNT_TARGET_SLUG")
            for k, v in authn.headers_for(ident, slug_or_path=(af or sslug)).items():
                h.setdefault(k, v)
        except Exception:  # noqa: BLE001
            pass
    # Adaptive rate limiting
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    _wait_for_host(host)
    chosen_proxy = _pick_proxy(proxy, proxy_list)
    _non_idempotent = method.upper() in ("POST", "PUT", "PATCH", "DELETE")
    # Try curl_cffi first (TLS impersonation), fall back to requests
    try:
        from curl_cffi import requests as cr
        _verify = os.environ.get("HUNT_TLS_VERIFY", "1") != "0"
        kw = {"impersonate": imp, "timeout": timeout, "headers": h, "verify": _verify}
        if chosen_proxy:
            kw["proxies"] = {"http": chosen_proxy, "https": chosen_proxy}
        r = cr.request(method.upper(), url, data=data, allow_redirects=allow_redirects, **kw)
        _rate_limit(host, r.status_code)
        rh = {k.lower(): v for k, v in r.headers.items()}
        # Validate redirect destination against scope
        if _SCOPE_GUARD and not _bypass_scope and r.status_code in (301, 302, 303, 307, 308):
            loc = rh.get("location", "")
            if loc:
                reason = _SCOPE_GUARD.reject_reason(loc if "://" in loc else f"https://{host}{loc}")
                if reason:
                    rh["_redirect_blocked"] = reason
        return r.status_code, r.text, rh
    except ImportError:
        pass
    except Exception as e:  # noqa: BLE001
        _rate_limit(host, 0)
        if _non_idempotent:
            return 0, "", {"_error": f"transport error (not retried — non-idempotent {method}): {e}"}
        # fall through to requests for idempotent methods only
    try:
        sess = _get_session()
        _verify = os.environ.get("HUNT_TLS_VERIFY", "1") != "0"
        kw = {"timeout": timeout, "headers": h, "verify": _verify}
        if chosen_proxy:
            kw["proxies"] = {"http": chosen_proxy, "https": chosen_proxy}
        r = sess.request(method.upper(), url, data=data, allow_redirects=allow_redirects, **kw)
        _rate_limit(host, r.status_code)
        rh = {k.lower(): v for k, v in r.headers.items()}
        if _SCOPE_GUARD and not _bypass_scope and r.status_code in (301, 302, 303, 307, 308):
            loc = rh.get("location", "")
            if loc:
                reason = _SCOPE_GUARD.reject_reason(loc if "://" in loc else f"https://{host}{loc}")
                if reason:
                    rh["_redirect_blocked"] = reason
        return r.status_code, r.text, rh
    except ImportError:
        return 0, "", {"_error": "neither curl_cffi nor requests available"}
    except Exception as e:  # noqa: BLE001
        _rate_limit(host, 0)
        return 0, "", {"_error": str(e)}


def _main(argv):
    ident = slug = None
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--as", "--ident") and i + 1 < len(argv):
            ident = argv[i + 1]; i += 2; continue
        if a == "--slug" and i + 1 < len(argv):
            slug = argv[i + 1]; i += 2; continue
        pos.append(a); i += 1
    if not pos:
        print("usage: netget.py <METHOD> <URL> [body] [--as A|B] [--slug <target>]", file=sys.stderr)
        return 2
    if len(pos) == 1:
        method, url, body = "GET", pos[0], None
    else:
        method, url, body = pos[0], pos[1], (pos[2] if len(pos) > 2 else None)
    hdrs = {}
    if body:
        try:
            json.loads(body)
            hdrs["Content-Type"] = "application/json"
        except ValueError:
            pass
    code, text, h = get(url, method=method, data=body, headers=hdrs, ident=ident, slug=slug)
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
