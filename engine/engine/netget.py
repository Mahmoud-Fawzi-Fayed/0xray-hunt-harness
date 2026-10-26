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

# Egress policy broker — enforces prohibited methods, required headers, audit trail
_EGRESS_POLICY = None

# Evidence pipeline — auto-record HTTP observations when an engagement dir is set
_EVIDENCE_DIR = None
_CURRENT_CASE_ID = threading.local()


def set_evidence_dir(path):
    global _EVIDENCE_DIR
    _EVIDENCE_DIR = path


def set_current_case(case_id):
    _CURRENT_CASE_ID.value = case_id


def clear_current_case():
    _CURRENT_CASE_ID.value = None


def _record_obs(method, url, req_headers, resp_status, resp_body, ident):
    edir = _EVIDENCE_DIR
    if not edir or resp_status <= 0:
        return
    try:
        import evidence as EV
        case_id = getattr(_CURRENT_CASE_ID, "value", None)
        EV.record_observation(
            edir, method.upper(), url,
            req_headers=req_headers, resp_status=resp_status, resp_body=resp_body,
            identity=ident, case_id=case_id,
            policy_id=getattr(_SCOPE_GUARD, "name", None))
    except Exception:  # noqa: BLE001
        pass


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


def set_scope_guard(scope, allow_intrusive=False):
    """Set the module-level scope guard. Called by engine at init."""
    global _SCOPE_GUARD, _EGRESS_POLICY
    _SCOPE_GUARD = scope
    # Also set up egress policy broker from scope
    if scope:
        try:
            import egress as _EG
            _EGRESS_POLICY = _EG.EgressPolicy(scope=scope, allow_intrusive=allow_intrusive)
            _EG.set_egress_policy(_EGRESS_POLICY)
        except Exception:
            _EGRESS_POLICY = None


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

_MAX_REQUESTS = int(os.environ.get("HUNT_MAX_REQUESTS", "5000") or 5000)
_request_count = 0

class BudgetExhausted(Exception):
    pass

def request_count():
    return _request_count

def reset_request_count():
    global _request_count
    _request_count = 0


def _is_localhost(url):
    """True when the URL targets a loopback address (selftest, local dev)."""
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
        return host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")
    except Exception:
        return False


_MAX_REDIRECT_HOPS = int(os.environ.get("HUNT_MAX_REDIRECTS", "5") or 5)


def follow_redirects(url, method="GET", data=None, headers=None, timeout=None,
                     ident=None, slug=None, max_hops=None):
    """Follow redirects safely — each hop re-authorized against scope, credentials stripped on origin change."""
    from urllib.parse import urlparse, urljoin
    hops = max_hops or _MAX_REDIRECT_HOPS
    current_url = url
    current_headers = dict(headers or {})
    prev_origin = None
    for _ in range(hops):
        code, text, rh = get(current_url, method=method, data=data, headers=current_headers,
                             timeout=timeout, ident=ident, slug=slug)
        if code not in (301, 302, 303, 307, 308):
            return code, text, rh
        loc = rh.get("location", "")
        if not loc:
            return code, text, rh
        if rh.get("_redirect_blocked"):
            return 0, "", {"_error": f"redirect to out-of-scope: {loc}", "_redirect_blocked": rh["_redirect_blocked"]}
        next_url = urljoin(current_url, loc)
        cur_parsed = urlparse(current_url)
        next_parsed = urlparse(next_url)
        cur_origin = f"{cur_parsed.scheme}://{cur_parsed.netloc}"
        next_origin = f"{next_parsed.scheme}://{next_parsed.netloc}"
        if cur_origin != next_origin:
            for k in list(current_headers):
                if k.lower() in ("authorization", "cookie", "x-api-key"):
                    del current_headers[k]
        if code == 303:
            method = "GET"
            data = None
        current_url = next_url
    return 0, "", {"_error": f"too many redirects ({hops} hops)"}


def get(url, method="GET", data=None, headers=None, timeout=None, ident=None, slug=None, allow_redirects=False):
    """Return (status_code:int, text:str, headers:dict). status 0 on transport error (see headers['_error']).
    ident 'A'/'B' loads that stored session (cookie/bearer/headers) for authenticated + cross-account tests."""
    if timeout is None:
        timeout = _DEFAULT_TIMEOUT
    # Egress policy check (prohibited methods, scope, audit)
    if _EGRESS_POLICY:
        try:
            import egress as _EG
            decision = _EGRESS_POLICY.check_egress(method, url, headers)
            _EGRESS_POLICY.record_decision(method, url, decision)
            if not decision.allowed:
                return 0, "", {"_error": f"egress denied: {decision.reason}"}
        except Exception:
            pass
    # Scope guard (defense-in-depth, also covers case where egress policy not loaded)
    if _SCOPE_GUARD:
        reason = _SCOPE_GUARD.reject_reason(url)
        if reason:
            return 0, "", {"_error": f"scope violation: {reason}"}
    elif not _is_localhost(url):
        return 0, "", {"_error": "no scope guard set — refusing non-localhost request (call set_scope_guard first)"}
    global _request_count
    _request_count += 1
    if _request_count > _MAX_REQUESTS:
        return 0, "", {"_error": f"request budget exhausted ({_MAX_REQUESTS})"}
    ua, imp, proxy, proxy_list = _cfg()
    h = dict(headers or {})
    if ua:
        h.setdefault("User-Agent", ua)
    # Inject required headers from egress policy
    if _EGRESS_POLICY:
        try:
            h = _EGRESS_POLICY.inject_required_headers(h)
        except Exception:
            pass
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
        r = cr.request(method.upper(), url, data=data, allow_redirects=False, **kw)
        _rate_limit(host, r.status_code)
        rh = {k.lower(): v for k, v in r.headers.items()}
        # Validate redirect destination against scope
        if _SCOPE_GUARD and r.status_code in (301, 302, 303, 307, 308):
            loc = rh.get("location", "")
            if loc:
                reason = _SCOPE_GUARD.reject_reason(loc if "://" in loc else f"https://{host}{loc}")
                if reason:
                    rh["_redirect_blocked"] = reason
        _record_obs(method, url, h, r.status_code, r.text, ident)
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
        r = sess.request(method.upper(), url, data=data, allow_redirects=False, **kw)
        _rate_limit(host, r.status_code)
        rh = {k.lower(): v for k, v in r.headers.items()}
        if _SCOPE_GUARD and r.status_code in (301, 302, 303, 307, 308):
            loc = rh.get("location", "")
            if loc:
                reason = _SCOPE_GUARD.reject_reason(loc if "://" in loc else f"https://{host}{loc}")
                if reason:
                    rh["_redirect_blocked"] = reason
        _record_obs(method, url, h, r.status_code, r.text, ident)
        return r.status_code, r.text, rh
    except ImportError:
        return 0, "", {"_error": "neither curl_cffi nor requests available"}
    except Exception as e:  # noqa: BLE001
        _rate_limit(host, 0)
        return 0, "", {"_error": str(e)}


def _load_scope_for_cli(scope_file=None, slug=None):
    """Resolve and install scope guard for CLI/subprocess use. Returns True on success."""
    try:
        from scope import Scope
    except ImportError:
        print("ERROR: scope.py not importable — cannot enforce policy", file=sys.stderr)
        return False
    # Explicit --scope-file takes priority
    if scope_file:
        if not os.path.isfile(scope_file):
            print(f"ERROR: scope file not found: {scope_file}", file=sys.stderr)
            return False
        try:
            sc = Scope.load(scope_file)
            set_scope_guard(sc)
            return True
        except Exception as e:
            print(f"ERROR: invalid scope file {scope_file}: {e}", file=sys.stderr)
            return False
    # Resolve from --slug via engagement directory
    if slug:
        base = os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements"))
        for candidate in [
            os.path.join(base, "_targets", slug + ".json"),
            os.path.join(base, slug, "scope.json"),
        ]:
            if os.path.isfile(candidate):
                try:
                    sc = Scope.load(candidate)
                    set_scope_guard(sc)
                    return True
                except Exception:
                    continue
        print(f"ERROR: no scope file found for slug '{slug}'", file=sys.stderr)
        return False
    return False


def _main(argv):
    if not argv or "--help" in argv or "-h" in argv:
        print("usage: netget.py <METHOD> <URL> [body] [--as A|B] [--slug <target>] [--scope-file <path>]",
              file=sys.stderr)
        return 0
    ident = slug = scope_file = None
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--as", "--ident") and i + 1 < len(argv):
            ident = argv[i + 1]; i += 2; continue
        if a == "--slug" and i + 1 < len(argv):
            slug = argv[i + 1]; i += 2; continue
        if a == "--scope-file" and i + 1 < len(argv):
            scope_file = argv[i + 1]; i += 2; continue
        pos.append(a); i += 1
    if not pos:
        print("usage: netget.py <METHOD> <URL> [body] [--as A|B] [--slug <target>] [--scope-file <path>]",
              file=sys.stderr)
        return 0
    if len(pos) == 1:
        method, url, body = "GET", pos[0], None
    else:
        method, url, body = pos[0], pos[1], (pos[2] if len(pos) > 2 else None)
    # Initialize evidence dir from environment for subprocess capture
    if os.environ.get("HUNT_EVIDENCE_DIR") and not _EVIDENCE_DIR:
        set_evidence_dir(os.environ["HUNT_EVIDENCE_DIR"])
    if os.environ.get("HUNT_CASE_ID"):
        set_current_case(os.environ["HUNT_CASE_ID"])
    # Load scope guard before any request — fail-closed for non-localhost
    if not _is_localhost(url):
        if not _load_scope_for_cli(scope_file=scope_file, slug=slug):
            print(f"ERROR: no valid scope policy — refusing request to {url}", file=sys.stderr)
            print("Provide --scope-file <path> or --slug <target> to authorize requests.", file=sys.stderr)
            return 1
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


def _selftest():
    """Offline self-test: scope guard, rate-limit state, budget tracking, header merging."""
    import scope as S

    # scope guard blocks out-of-scope
    sg = S.Scope(["example.com"], ["admin.example.com"])
    set_scope_guard(sg)
    code, _, h = get("https://evil.com/test")
    err = h.get("_error", "")
    assert code == 0 and ("scope violation" in err or "egress denied" in err or "scope:" in err), f"expected scope block: {code} {h}"
    code2, _, h2 = get("https://admin.example.com/x")
    err2 = h2.get("_error", "")
    assert code2 == 0 and ("scope violation" in err2 or "egress denied" in err2 or "scope:" in err2), f"expected out-of-scope block: {code2} {h2}"
    set_scope_guard(None)

    # fail-closed: no scope guard + non-localhost = blocked
    code_fc, _, h_fc = get("https://example.com/test")
    assert code_fc == 0 and "no scope guard" in h_fc.get("_error", ""), f"expected fail-closed block: {code_fc} {h_fc}"
    # localhost is allowed without scope guard (selftest, local dev)
    code_lo, _, h_lo = get("http://127.0.0.1:1/test", timeout=1)
    assert "no scope guard" not in h_lo.get("_error", ""), f"localhost should not be blocked: {h_lo}"

    # budget tracking (use localhost — scope guard not needed)
    global _request_count, _MAX_REQUESTS
    saved_count, saved_max = _request_count, _MAX_REQUESTS
    _request_count = 0
    _MAX_REQUESTS = 2
    assert request_count() == 0
    get("http://127.0.0.1:1/status/200", timeout=1)
    assert request_count() >= 1
    _request_count = _MAX_REQUESTS + 1
    code3, _, h3 = get("http://127.0.0.1:1/status/200", timeout=1)
    assert code3 == 0 and "budget" in h3.get("_error", ""), f"expected budget block: {code3} {h3}"
    _request_count, _MAX_REQUESTS = saved_count, saved_max

    # rate limiter state structure
    assert isinstance(_RL_STATE, dict)
    assert _RL_MIN_DELAY > 0

    # CLI scope loading — _load_scope_for_cli
    import tempfile
    td = tempfile.mkdtemp()
    scope_path = os.path.join(td, "test-scope.json")
    with open(scope_path, "w") as f:
        json.dump({"name": "cli-test", "in_scope": ["example.com"], "out_of_scope": []}, f)
    set_scope_guard(None)
    assert _load_scope_for_cli(scope_file=scope_path), "should load from --scope-file"
    assert _SCOPE_GUARD is not None, "scope guard should be set after CLI load"
    # Now example.com should be in-scope
    code_cli, _, h_cli = get("https://example.com/test", timeout=3)
    assert "no scope guard" not in h_cli.get("_error", ""), "example.com should pass scope after CLI load"
    set_scope_guard(None)
    # Missing scope file should fail
    assert not _load_scope_for_cli(scope_file="/nonexistent/scope.json"), "missing file should fail"
    # Slug resolution
    tgt_dir = os.path.join(td, "_targets")
    os.makedirs(tgt_dir, exist_ok=True)
    with open(os.path.join(tgt_dir, "test-prog.json"), "w") as f:
        json.dump({"name": "test-prog", "in_scope": ["httpbin.org"], "out_of_scope": []}, f)
    os.environ["BUGHUNTER_BASE"] = td
    set_scope_guard(None)
    assert _load_scope_for_cli(slug="test-prog"), "should load from slug"
    assert _SCOPE_GUARD is not None, "scope guard should be set from slug"
    set_scope_guard(None)
    assert not _load_scope_for_cli(slug="nonexistent-prog"), "missing slug should fail"
    os.environ.pop("BUGHUNTER_BASE", None)
    set_scope_guard(None)

    # Evidence auto-recording: set evidence dir, make a localhost request, verify observation stored
    global _EVIDENCE_DIR
    saved_edir = _EVIDENCE_DIR
    ev_dir = os.path.join(td, "evidence-test")
    os.makedirs(ev_dir, exist_ok=True)
    _EVIDENCE_DIR = ev_dir
    set_scope_guard(None)  # localhost doesn't need scope
    get("http://127.0.0.1:1/evidence-selftest", timeout=1)
    # Even a failed connection should not crash — _record_obs only fires for status > 0
    obs_file = os.path.join(ev_dir, "observations.jsonl")
    # transport error = status 0, so no observation should be written
    if os.path.exists(obs_file):
        with open(obs_file) as _of:
            lines = [l.strip() for l in _of if l.strip()]
            assert len(lines) == 0, f"transport error should not record observation, got {len(lines)}"
    _EVIDENCE_DIR = saved_edir

    print("netget.py self-test: PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(_selftest())
    sys.exit(_main(sys.argv[1:]))
