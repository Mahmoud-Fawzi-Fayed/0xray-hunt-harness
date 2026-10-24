#!/usr/bin/env python3
"""
authsession.py — provision and store an AUTHENTICATED test session so the hunt can reach the surface
behind login (where IDOR / broken-authz / business-logic bugs actually live). Fully guardrail-gated and
scoped: it only registers on in-scope hosts, uses a disposable mail.tm identity, respects the per-program
account cap, and never touches a real user's account.

Flow (agent-driven, so it works on ANY target's signup — not a hardcoded form):
  1. pick an in-scope auth host (prefer sandbox-login / sandbox-vendors / login / vendors / portal)
  2. mint a disposable identity (identity.py) with a live inbox
  3. drive a cursor-agent to register, confirm via the inbox, log in, and CAPTURE the session
     (cookies + any Authorization/token header) as JSON
  4. store it (chmod 600) for the hunt to reuse; the hunt injects it into authenticated test steps

  provision(program, scope)      -> {success, host, cookies, headers, notes} | {error}
  load(program) / valid(session) -> stored session for reuse
  auth_block(session, url)       -> the text injected into a hunt task when the host matches

CLI:
  python3 engine/authsession.py provision --program paddle
  python3 engine/authsession.py show      --program paddle
  python3 engine/authsession.py selftest        # hermetic (mock agent, no network)
"""
import argparse
import glob
import json
import os
import re
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import guardrails as G   # noqa: E402
import identity as I     # noqa: E402
import agent as A        # noqa: E402

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
# preference order for which in-scope host to register on (sandboxes first — usually open signup, softer).
# Matched LABEL-AWARE (against the subdomain label), so "app" selects app.foo.com but NOT apps.apple.com.
AUTH_HOST_PREF = ("sandbox-login", "sandbox-vendors", "sandbox-api", "login", "signin", "signup",
                  "register", "join", "secure", "auth", "sso", "vendor", "vendors", "onboard",
                  "onboarding", "customer-portal", "portal", "account", "accounts", "app", "my",
                  "dashboard", "prescription", "shop", "store", "www")

# Third-party storefronts / IdPs that commonly appear IN scope as "our mobile app / listing" but are NOT
# the program's own systems. We must never try to self-register there: it always fails (no open signup)
# and scripted account creation on someone else's platform would be abuse.
THIRDPARTY_APEX = {"apple.com", "itunes.apple.com", "play.google.com", "google.com", "microsoft.com",
                   "amazon.com", "aws.amazon.com", "facebook.com", "instagram.com", "github.com",
                   "gitlab.com", "okta.com", "auth0.com", "cloudflareaccess.com"}


def _request(url, data=None, headers=None, method=None):
    """Build a Request that keeps header names exactly as given.

    stdlib Request title-cases names; some APIs treat custom auth headers as case-sensitive.
    """
    import urllib.request
    class Raw(urllib.request.Request):
        def add_header(self, key, val):
            self.headers[key] = val
        def add_unredirected_header(self, key, val):
            self.unredirected_hdrs[key] = val
    kw = {}
    if data is not None:
        kw["data"] = data
    if method:
        kw["method"] = method
    return Raw(url, headers=dict(headers or {}), **kw)


def _is_thirdparty(host):
    h = G._host_of(host)
    apex = ".".join(h.split(".")[-2:]) if h.count(".") >= 1 else h
    return h in THIRDPARTY_APEX or apex in THIRDPARTY_APEX


def _clean_host(h):
    """Reduce any host-ish string to a BARE hostname safe to put in a URL. The signup agent sometimes
    returns a descriptive host (e.g. 'sandbox-login.paddle.com (signup API: sandbox-api.paddle.com)');
    left unsanitized, the space/parens later crash urllib ('URL can't contain control characters')."""
    h = str(h or "").strip()
    h = re.sub(r"(?i)^https?://", "", h)          # strip scheme
    h = h.split("/", 1)[0]                         # strip any path
    h = re.split(r"[\s(,;]", h, maxsplit=1)[0]     # cut at first space / '(' / ',' / ';' (annotations)
    return h.strip().strip(".")


def _apex(h):
    return G._host_of(_clean_host(h))


def pick_auth_host(scope):
    """Choose the best in-scope host to register on. Returns a hostname or None.
    - excludes third-party storefronts/IdPs (apps.apple.com etc.) — not the program's own systems
    - matches preferences against the SUBDOMAIN LABEL so 'app' picks app.x.com, not apps.apple.com
    - falls back to the program's DOMINANT apex (its primary domain), shortest host first."""
    scope = scope if isinstance(scope, dict) else {}
    hosts = [G._host_of(h) for h in scope.get("in_scope", []) if "*" not in str(h)]
    hosts = [h for h in hosts if h and not _is_thirdparty(h)]
    if not hosts:
        return None
    label0 = lambda h: h.split(".")[0]
    for pref in AUTH_HOST_PREF:
        for h in hosts:
            if label0(h) == pref or label0(h).startswith(pref):
                return h
    from collections import Counter
    freq = Counter(".".join(h.split(".")[-2:]) for h in hosts)   # program's own domain dominates
    return sorted(hosts, key=lambda h: (-freq[".".join(h.split(".")[-2:])], len(h)))[0]


def _vault(program, base):
    d = os.path.join(os.path.expanduser(base), "_identity")
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return os.path.join(d, G._slug(program) + "-session.json")


def load(program, base=DEFAULT_BASE):
    try:
        s = json.load(open(_vault(program, base)))
    except (OSError, json.JSONDecodeError):
        return None
    if valid(s):                                    # back-fill the authn A/B store for sessions saved BEFORE the
        try:                                        # mirror existed, so authz.py / netget --as A can use them
            import authn as _an
            if not _an.configured(program, base):
                _mirror_to_authn(program, s, base)
        except Exception:  # noqa: BLE001
            pass
    return s


def save(program, session, base=DEFAULT_BASE):
    path = _vault(program, base)
    json.dump(session, open(path, "w"), indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    _mirror_to_authn(program, session, base)   # keep the authn A/B store (browser/netget/authz) in sync
    return path


def _creds_path(program, base=DEFAULT_BASE):
    d = os.path.join(os.path.expanduser(base), "_identity")
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return os.path.join(d, G._slug(program) + "-creds.json")


def load_creds(program, base=DEFAULT_BASE):
    try:
        c = json.load(open(_creds_path(program, base)))
        return c if isinstance(c, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_login(program, ident, host, user, password, login_url, extra_headers=None,
               user_key="username", pass_key="password", probe=None, token_header=None,
               token_json_key=None, session_headers=None, cookies=None, method=None,
               base=DEFAULT_BASE):
    """Store operator-owned login details so an expired session can be refreshed.

    The login URL, JSON field names, and auth header name come from THIS paste/vault —
    not from an engine path catalog. Password never goes in logs. Cookie-only
    pastes refresh by replaying login_url with the stored cookie jar.
    """
    ident = "B" if str(ident).strip().upper() == "B" else "A"
    blob = load_creds(program, base)
    ck = dict(cookies) if isinstance(cookies, dict) else {}
    rec = {
        "host": G._host_of(host) or host,
        "user": user,
        "password": password,
        "login_url": login_url,
        "method": (method or ("POST" if password else "GET")).upper(),
        "user_key": user_key or "username",
        "pass_key": pass_key or "password",
        "extra_headers": dict(extra_headers or {}),
        "session_headers": dict(session_headers or {}),
        "token_header": token_header,
        "token_json_key": token_json_key,
        "cookies": ck,
        "probe": probe,
        "ts": time.time(),
    }
    blob[ident] = rec
    path = _creds_path(program, base)
    json.dump(blob, open(path, "w"), indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return {"ok": True, "program": G._slug(program), "ident": ident, "host": rec["host"],
            "user": user, "login_url_host": G._host_of(login_url)}


def _extract_session(resp_headers, body, jar_cookies):
    """Pull cookies + auth headers out of a login response. No product-specific path list."""
    cookies = dict(jar_cookies or {})
    hdrs = {}
    for k, v in (resp_headers or []):
        kl = str(k).lower()
        if kl in ("set-cookie", "content-type", "date", "server", "vary", "location"):
            continue
        if any(x in kl for x in ("auth", "api-key", "apikey", "token", "session")):
            hdrs[k] = v
    data = None
    try:
        data = json.loads(body or b"" if isinstance(body, (bytes, bytearray)) else (body or ""))
    except Exception:  # noqa: BLE001
        data = None

    def walk(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                kl = str(key).lower()
                if isinstance(val, str) and 8 <= len(val) <= 8192:
                    if any(x in kl for x in ("api_key", "apikey", "access_token", "auth_token",
                                             "session_token", "csrf")):
                        hdrs[key] = val
                    elif kl in ("token", "key") and re.fullmatch(r"[A-Za-z0-9_\-.]{16,}", val):
                        hdrs[key] = val
                    elif kl == "id" and re.fullmatch(r"[A-Za-z0-9_\-.]{16,}", val):
                        hdrs.setdefault("_token", val)
                walk(val)
        elif isinstance(obj, list):
            for it in obj[:20]:
                walk(it)
    walk(data)
    return cookies, hdrs, data if isinstance(data, dict) else {}


def relogin(program, ident="A", base=DEFAULT_BASE, timeout=20):
    """Replay the stored login_url (password POST or cookie GET). Used when a session expires.

    Nothing here is a product catalog — only this program's creds vault.
    """
    import urllib.request
    import urllib.error
    import http.cookiejar
    ident = "B" if str(ident).strip().upper() == "B" else "A"
    rec = (load_creds(program, base) or {}).get(ident) or {}
    url = rec.get("login_url") or ""
    user = rec.get("user") or ""
    password = rec.get("password") or ""
    stored_ck = dict(rec.get("cookies") or {}) if isinstance(rec.get("cookies"), dict) else {}
    if not (url.startswith("http") and (password or stored_ck)):
        return {"error": "no stored login_url with password or cookies for this ident — paste a live session"}
    method = str(rec.get("method") or ("POST" if password else "GET")).upper()
    extra = dict(rec.get("extra_headers") or {})
    extra.setdefault("Accept", "application/json")
    extra.setdefault("User-Agent",
                     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    payload = None
    if password and method == "POST":
        uk, pk = rec.get("user_key") or "username", rec.get("pass_key") or "password"
        payload = json.dumps({uk: user, pk: password}).encode("utf-8")
        extra.setdefault("Content-Type", "application/json")
    elif method == "GET":
        extra.pop("Content-Type", None)
    if stored_ck:
        extra["Cookie"] = "; ".join(f"{k}={v}" for k, v in stored_ck.items())
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req = _request(url, data=payload, headers=extra, method=method)
    try:
        r = opener.open(req, timeout=timeout)
        code, body, rh = r.status, r.read(8000), r.headers.items()
    except urllib.error.HTTPError as e:
        code, body, rh = e.code, (e.read(8000) if hasattr(e, "read") else b""), getattr(e, "headers", {})
        rh = rh.items() if hasattr(rh, "items") else []
    except Exception as e:  # noqa: BLE001
        return {"error": f"login request failed: {type(e).__name__}"}
    jar_cookies = {c.name: c.value for c in jar}
    cookies, hdrs, data = _extract_session(rh, body, jar_cookies)
    merged = dict(stored_ck)
    merged.update(cookies)
    cookies = merged
    th = rec.get("token_header")
    tjk = rec.get("token_json_key")
    token = data.get(tjk) if tjk and isinstance(data.get(tjk), str) else None
    token = token or hdrs.pop("_token", None)
    if not token:
        for k in ("access_token", "token", "id_token"):
            v = data.get(k)
            if isinstance(v, str) and len(v) >= 8:
                token = v
                break
    if token and th:
        hdrs[th] = token
    elif token and not any(str(k).lower() == "authorization" for k in hdrs):
        hdrs["Authorization"] = token if str(token).lower().startswith("bearer ") else ("Bearer " + token)
    hdrs.pop("_token", None)
    for junk in ("access_token", "id_token", "refresh_token", "token"):
        if junk in hdrs and any(str(k).lower() == "authorization" for k in hdrs):
            hdrs.pop(junk, None)
    if token:
        nt = _first_jwt(token) or str(token)
        for k, v in list(cookies.items()):
            if not _jwt_expired_value(v) and not (
                _first_jwt(v) and (_jwt_payload(_first_jwt(v) or "") or {}).get("typ")
                == (_jwt_payload(nt) or {}).get("typ")
            ):
                continue
            old = str(v)
            fj = _first_jwt(old)
            cookies[k] = (nt + old[len(fj):]) if fj and old.startswith(fj) else nt
    for k, v in (rec.get("session_headers") or {}).items():
        if k and v and k not in hdrs:
            hdrs[k] = v
    if extra.get("User-Agent"):
        hdrs.setdefault("User-Agent", extra["User-Agent"])
    user_out = user
    for k in ("username", "email", "user", "login"):
        v = data.get(k)
        if isinstance(v, str) and "@" in v:
            user_out = v
            break
    if not cookies and not hdrs:
        return {"error": f"login HTTP {code} returned no session cookies/headers"}
    if cookies:
        rec["cookies"] = cookies
        rec["ts"] = time.time()
        blob = load_creds(program, base)
        blob[ident] = rec
        path = _creds_path(program, base)
        json.dump(blob, open(path, "w"), indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    probe = rec.get("probe") if isinstance(rec.get("probe"), str) else None
    if probe and probe.startswith("http"):
        probe_h = {**{"Accept": extra.get("Accept") or "application/json",
                      "User-Agent": extra.get("User-Agent") or "Mozilla/5.0"}, **hdrs}
        if cookies:
            probe_h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        try:
            preq = _request(probe, headers=probe_h)
            pr = urllib.request.urlopen(preq, timeout=timeout)
            pcode = pr.status
            pr.read(200)
        except urllib.error.HTTPError as e:
            pcode = e.code
        except Exception:  # noqa: BLE001
            pcode = None
        if not (isinstance(pcode, int) and 200 <= pcode < 300):
            return {"error": "login HTTP %s but probe HTTP %s — token_header/probe mismatch" % (code, pcode)}
    r = set_manual(program, rec.get("host") or G._host_of(url), cookie=cookies, headers=hdrs,
                   user=user_out, ident=ident, probe=probe, base=base)
    if r.get("ok"):
        r["relogin"] = True
        r["http"] = code
    return r


def _mirror_to_authn(program, session, base, ident="A"):
    """Mirror the operator/provisioned session into the authn A/B store (<base>/_auth/<slug>.json) as
    identity `ident` (default A) — so the authn-based tools all carry the SAME logged-in session the agent
    uses: headless browser recon (authed SPA capture), netget --as A, and the authz.py IDOR/BOLA sweep.
    Without this, authed recon runs UNauthenticated even when a session exists. Best-effort; never raises."""
    try:
        if not valid(session):
            return
        import authn
        cookies = session.get("cookies") or {}
        cstr = ("; ".join(f"{k}={v}" for k, v in cookies.items())
                if isinstance(cookies, dict) else str(cookies))
        hdrs = {k: v for k, v in (session.get("headers") or {}).items() if k.lower() != "cookie"}
        bearer = hdrs.pop("Authorization", "") or hdrs.pop("authorization", "")
        bearer = re.sub(r"(?i)^bearer\s+", "", str(bearer)).strip()
        authn.save(program, ident, cookie=cstr or None, bearer=bearer or None,
                   headers=hdrs or None, host=session.get("host"), base=base, replace=True)
    except Exception:  # noqa: BLE001
        pass


def valid(session):
    """A session is usable if it carries at least one cookie or an auth header."""
    if not isinstance(session, dict) or not session.get("success"):
        return False
    return bool(session.get("cookies")) or bool(session.get("headers"))


def _first_jwt(s):
    """First compact JWT in a header/cookie value. Ignores trailing concatenated blobs. No secrets logged."""
    s = str(s or "").strip()
    if s.lower().startswith("bearer "):
        s = s.split(None, 1)[-1].strip()
    cand = s.split("+", 1)[0]
    parts = cand.split(".")
    if len(parts) >= 3 and parts[0].startswith("eyJ"):
        return cand
    return None


def _jwt_payload(tok):
    parts = str(tok or "").split(".")
    if len(parts) < 2:
        return None
    import base64
    pad = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        p = json.loads(base64.urlsafe_b64decode(pad.encode("ascii")))
    except Exception:  # noqa: BLE001
        return None
    return p if isinstance(p, dict) else None


def _jwt_expired_value(s):
    tok = _first_jwt(s)
    if not tok:
        return False
    payload = _jwt_payload(tok)
    exp = payload.get("exp") if payload else None
    if not isinstance(exp, (int, float)):
        return False
    return exp < (time.time() - 30)


def _jwt_expired(headers, cookies=None):
    """True when any JWT in headers or cookies has exp in the past. No token is logged."""
    for v in list((headers or {}).values()) + list((cookies or {}).values()):
        if _jwt_expired_value(v):
            return True
    return False


def _bearer_from_cookies(cookies):
    """Pick the best access-token-looking JWT from a cookie jar to send as Authorization."""
    best, score = None, -1
    for v in (cookies or {}).values():
        tok = _first_jwt(v)
        if not tok:
            continue
        p = _jwt_payload(tok) or {}
        sc = 0
        typ = str(p.get("typ") or "").lower()
        if "at" in typ or "access" in typ:
            sc += 3
        if p.get("aud") or p.get("scp"):
            sc += 2
        if p.get("exp"):
            sc += 1
        if sc > score:
            best, score = tok, sc
    return best


def note_live(program, url, base=DEFAULT_BASE):
    """Remember the URL that proved this login, so the next health check is that URL — not a catalog."""
    if not isinstance(url, str) or not url.startswith("http") or " " in url or "(" in url:
        return
    sess = load(program, base)
    if not valid(sess):
        return
    if G._host_of(url) != G._host_of(sess.get("host") or ""):
        return
    if sess.get("probe"):
        return
    sess["probe"] = url.split("#")[0]
    save(program, sess, base)


def _probes_for(session, program=None, base=None):
    """URLs to re-check, from this session and this program's live surface. No built-in path list.

    If the login named a probe, that URL is the only health check — extra surface paths can
    401 for authorization (other tenant, other role) while the session is still live.
    """
    host = G._host_of(session.get("host") or "")
    probes = []
    for key in ("probe", "health_url"):
        u = session.get(key)
        if isinstance(u, str) and u.startswith("http") and " " not in u and "(" not in u:
            probes.append(u.split("#")[0])
    if probes:
        return probes[:2]
    slug = program or session.get("program")
    root = os.path.expanduser(base or DEFAULT_BASE)
    if slug and host:
        try:
            st = json.load(open(os.path.join(root, slug, "state.json")))
        except (OSError, json.JSONDecodeError):
            st = {}
        scored = []
        for s in st.get("surface") or []:
            u = (s.get("url") or "").split("#")[0]
            if not u.startswith("http") or " " in u or "(" in u:
                continue
            if G._host_of(u) != host:
                continue
            if re.search(r"\.(png|jpe?g|gif|svg|css|js|mjs|map|woff2?|mp4|webm)(\?|$)", u, re.I):
                continue
            apiish = 1 if re.search(r"/api/|/gw/|/v[0-9]+/|/auth/|/rest/", u, re.I) else 0
            scored.append((apiish, u.split("?")[0]))
        scored.sort(reverse=True)
        for _, u in scored:
            if u not in probes:
                probes.append(u)
            if len(probes) >= 3:
                break
    return probes[:3]


def site_rejects(session, timeout=12, program=None, base=None):
    """True when the site itself refuses this session.

    Rechecks the URL that proved the login, then up to two APIs already on this
    program's surface. There is no built-in path or product catalog. A public
    homepage 200 is not proof of login; a 401 is a dead session. Network errors
    do not count as rejection.
    """
    if not valid(session):
        return False
    host = G._host_of(session.get("host") or "")
    if not host:
        return False
    import urllib.request
    cookies = session.get("cookies") or {}
    hdrs = {k: v for k, v in (session.get("headers") or {}).items() if k.lower() != "cookie"}
    if _jwt_expired(hdrs, cookies if isinstance(cookies, dict) else None):
        return True
    if isinstance(cookies, dict) and cookies:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if not any(str(k).lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    if not any(str(k).lower() == "accept" for k in hdrs):
        hdrs["Accept"] = "application/json"

    def _open(url):
        req = _request(url, headers=hdrs)
        try:
            r = urllib.request.urlopen(req, timeout=timeout)
            return r.status, r.read(800)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
            body = e.read(800) if hasattr(e, "read") else b""
            return code, body

    saw_401 = False
    for url in _probes_for(session, program=program, base=base):
        code, body = _open(url)
        if code == 401:
            saw_401 = True
            continue
        raw = (body or b"").lstrip()
        if code and 200 <= code < 300:
            flat = re.sub(rb"\s+", b"", raw[:800])
            if b'"loggedIn":false' in flat:
                saw_401 = True
                continue
            return False
    if saw_401:
        return True
    code, _body = _open("https://" + host + "/")
    return code == 401


def _parse_cookie(s):
    """Parse cookies from ANY common paste format and return (cookies {name:value}, domains set):
      - a browser-extension JSON export (Cookie-Editor / EditThisCookie: a list of {name,value,domain,…})
      - a pasted `curl` command (uses its -b / --cookie value)
      - a raw 'Cookie:' header, or 'name=value; name2=value2'."""
    s = str(s or "").strip()
    out, domains = {}, set()
    if s[:1] in "[{":                                    # JSON export from a cookie extension
        try:
            data = json.loads(s)
            items = data if isinstance(data, list) else (data.get("cookies") if isinstance(data, dict) else [])
            for it in (items or []):
                if isinstance(it, dict) and it.get("name"):
                    out[str(it["name"])] = str(it.get("value", ""))
                    if it.get("domain"):
                        domains.add(str(it["domain"]).lstrip("."))
            if out:
                return out, domains
        except Exception:  # noqa: BLE001
            pass
    m = re.search(r"(?:-b|--cookie)\s+(['\"])(.*?)\1", s, re.S)   # a pasted curl command
    if m:
        s = m.group(2)
    for part in re.split(r";|\n", s):                    # raw Cookie header / k=v; k2=v2
        part = part.strip()
        if part.lower().startswith("cookie:"):
            part = part[7:].strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            if k and " " not in k and '"' not in k and ":" not in k:   # skip JSON-ish / header junk
                out[k] = v.strip()
    return out, domains


def set_manual(program, host, cookie=None, headers=None, token=None, user=None,
               base=DEFAULT_BASE, ident="A", probe=None):
    """Store an OPERATOR-PROVIDED session (a ready test account) so the hunt tests AUTHENTICATED — the easy
    path when a program forbids self-registration. `cookie` may be a raw Cookie-header string or a dict;
    `token` becomes an `Authorization: Bearer` header. The host must be in the program's scope. Returns a
    dict (ok / error)."""
    slug = G._slug(program)
    cookies, domains = _parse_cookie(cookie) if isinstance(cookie, str) else (dict(cookie or {}), set())
    hdrs = dict(headers or {})
    tok = str(token or "").strip()
    if tok and tok not in ("eyJ…", "eyJ...", "..."):        # ignore the UI placeholder
        hdrs["Authorization"] = tok if tok.lower().startswith("bearer ") else ("Bearer " + tok)
    if not any(str(k).lower() == "authorization" for k in hdrs):
        btok = _bearer_from_cookies(cookies)
        if btok:
            hdrs["Authorization"] = "Bearer " + btok
    if not cookies and not hdrs:
        return {"error": "no cookies found — paste the Cookie header, a cookie-extension JSON export, "
                         "a curl command, or a token"}
    try:
        sd = json.load(open(os.path.join(os.path.expanduser(base), "_targets", slug + ".json")))
    except (OSError, json.JSONDecodeError):
        return {"error": f"unknown program {program!r} (add it first)"}
    try:
        import scope as _sc
        sc = _sc.Scope(sd.get("in_scope", []), sd.get("out_of_scope", []))
    except Exception:  # noqa: BLE001
        sc = None
    host = G._host_of(host) if host else ""
    if sc and (not host or not sc.in_scope_host(host)):     # derive an in-scope host from cookies/seeds
        cand = []
        for d in sorted(domains):
            cand += [d, "www." + d]
        cand += [G._host_of(x) for x in (sd.get("seeds") or [])]
        host = next((c for c in cand if c and sc.in_scope_host(c)), host)
    if sc and (not host or not sc.in_scope_host(host)):
        ins = sd.get("in_scope") or []
        ex = [p for p in ins if "*" not in p and "/" not in p][:3] \
            or ["www." + p.lstrip("*.") for p in ins if p.startswith("*.")][:3] \
            or ["a host in scope"]
        return {"error": f"couldn't pick an in-scope host for {program!r} (tried cookies + scope) — "
                         f"set Host to one of: {', '.join(ex)}"}
    ident = "B" if str(ident).strip().upper() == "B" else "A"
    sess = {"success": True, "host": host, "program": slug, "cookies": cookies, "headers": hdrs,
            "user": user or ("victim-B" if ident == "B" else "operator-provided"),
            "source": "manual", "ts": time.time()}
    if isinstance(probe, str) and probe.startswith("http"):
        sess["probe"] = probe.split("#")[0]
    if ident == "B":
        # a SECOND account for cross-account IDOR/BOLA (the victim). Store ONLY as authn 'B' — don't
        # replace the agent's primary session (A) or requeue the surface; the agent reaches B via
        # `netget --as B` / `authz.py diff` to prove A-reads-B's-data.
        _mirror_to_authn(program, sess, base, ident="B")
        return {"ok": True, "program": slug, "host": host, "ident": "B", "cookies": len(cookies),
                "headers": list(hdrs.keys()), "user": sess["user"], "requeued": 0}
    save(program, sess, base=base)
    # Relogin / a still-good paste must NOT wipe coverage. Only reopen URLs that were closed on a
    # login wall so the hunt retries those authenticated — everything else stays tested.
    requeued = 0
    try:
        sp = os.path.join(os.path.expanduser(base), slug, "state.json")
        stt = json.load(open(sp))
        tested = stt.get("tested") if isinstance(stt.get("tested"), dict) else {}
        notes = stt.get("hunt_notes") if isinstance(stt.get("hunt_notes"), dict) else {}
        for key, note in list(notes.items()):
            analysis = str((note or {}).get("analysis") if isinstance(note, dict) else "").lower()
            wall = any(x in analysis for x in ("401", "unauthorized", "authentication required")) and \
                any(x in analysis for x in ("unauthenticated", "login wall", "logged out", "no session"))
            if key in tested and wall:
                tested.pop(key, None)
                requeued += 1
            stt["tested"] = tested
            tmp = sp + ".tmp"
            json.dump(stt, open(tmp, "w"), indent=2)
            os.replace(tmp, sp)
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "program": slug, "host": host, "ident": "A", "cookies": len(cookies),
            "headers": list(hdrs.keys()), "user": sess["user"], "requeued": requeued}


def provision_b(program, base=DEFAULT_BASE, scope=None, host=None, timeout=None):
    """Provision a SECOND in-scope account and store it as authn identity 'B' (the cross-account IDOR/BOLA
    victim). Hard-gated: needs a valid primary session, no existing B, a self-register host, the guardrail
    account-cap, and a cooldown marker so an unattended caller NEVER spams signups. Best-effort; returns
    {'ok':True} or {'error':...}. Picked up by the next hunt round — no restart needed."""
    import authn
    slug = G._slug(program)
    if "B" in authn.identities(slug, base):
        return {"ok": True, "note": "B already present"}
    if not valid(load(program, base)):
        return {"error": "no valid primary (A) session — provision A first"}
    # cooldown: don't re-attempt B signup within the retry window (avoids unattended signup spam)
    mk = os.path.join(os.path.expanduser(base), "_identity", f"{slug}-B.attempt")
    cool = int(os.environ.get("HUNT_PROVISION_RETRY", "21600"))
    try:
        if os.path.isfile(mk) and (time.time() - os.path.getmtime(mk)) < cool:
            return {"error": "cooldown: B provisioning attempted recently"}
    except OSError:
        pass
    if scope is None:
        scope = G._load_scope(program, base)
    if not host:                                    # prefer the host where A already signed up successfully
        a = load(program, base)                     # (pick_auth_host may otherwise pick a harder KYC host)
        host = _clean_host(a.get("host", "")) if valid(a) else None
    host = host or pick_auth_host(scope)
    if not host:
        return {"error": "no in-scope auth host to register on"}
    ok, why = G.check(program, "register", url="https://" + host, scope=scope, base=base, log=False)
    if not ok:
        return {"error": why}
    os.makedirs(os.path.dirname(mk), exist_ok=True)
    open(mk, "w").write(str(time.time()))               # stamp BEFORE the attempt -> at most one try per window
    ident = I.new_identity(program, base=base, scope=scope)
    if ident.get("error"):
        return {"error": "identity: " + ident["error"]}
    if timeout is None:
        timeout = int(os.environ.get("HUNT_PROVISION_TIMEOUT", "600"))
    r = A.run_agent(_provision_task(program, host, ident), timeout=timeout, attempts=1)
    if r.get("error"):
        return {"error": "agent: " + r["error"]}
    data = A.extract_json(r.get("result", "")) or {}
    if not isinstance(data, dict) or not data.get("success"):
        return {"error": "signup did not complete", "notes": (data or {}).get("notes", "")}
    cookies = data.get("cookies") or {}
    cstr = "; ".join(f"{k}={v}" for k, v in cookies.items()) if isinstance(cookies, dict) else str(cookies)
    bearer = (data.get("headers") or {}).get("Authorization") or (data.get("headers") or {}).get("authorization")
    authn.save(slug, "B", cookie=cstr or None,
               bearer=re.sub(r"(?i)^bearer\s+", "", str(bearer or "")).strip() or None, base=base)
    G.audit(program, "login", True, "second account (B) captured for cross-account IDOR",
            url="https://" + host, base=base)
    return {"ok": True, "program": slug, "ident": "B", "user": data.get("user") or ident.get("email")}


def clear_manual(program, base=DEFAULT_BASE):
    """Remove the stored session for a program."""
    try:
        os.remove(_vault(program, base))
        return {"ok": True, "program": G._slug(program)}
    except OSError:
        return {"ok": False, "error": "no stored session"}


def status(base=DEFAULT_BASE):
    """Which programs currently have a usable stored session — for the panel's auth indicators."""
    out = {}
    for f in glob.glob(os.path.join(os.path.expanduser(base), "_identity", "*-session.json")):
        slug = os.path.basename(f)[:-len("-session.json")]
        try:
            s = json.load(open(f))
        except Exception:  # noqa: BLE001
            continue
        if valid(s):
            out[slug] = {"host": s.get("host"), "user": s.get("user"), "source": s.get("source", "auto"),
                         "cookies": len(s.get("cookies") or {}), "headers": list((s.get("headers") or {}).keys())}
    # annotate each program with the authn A/B identities present (B = a second, cross-account IDOR victim)
    try:
        import authn
        for f in glob.glob(os.path.join(os.path.expanduser(base), "_auth", "*.json")):
            slug = os.path.basename(f)[:-len(".json")]
            ids = authn.identities(slug, base)
            if ids:
                out.setdefault(slug, {"host": "", "user": "", "source": "authn",
                                      "cookies": 0, "headers": []})
                out[slug]["idents"] = ids
    except Exception:  # noqa: BLE001
        pass
    return out


def check_live(program, base=DEFAULT_BASE, timeout=12):
    """Panel/live verdict: same check the hunt uses (JWT exp + this session's probe / this
    program's own surface). No homepage marker catalog."""
    s = load(program, base)
    if not valid(s):
        return {"ok": False, "error": "no valid session stored for this program"}
    host = _clean_host(G._host_of(s.get("host", "")) or s.get("host", ""))
    if not host:
        return {"ok": False, "error": "stored session has no host"}
    rejected = site_rejects(s, timeout=timeout, program=program, base=base)
    probes = _probes_for(s, program=program, base=base)
    if rejected:
        return {"ok": True, "program": G._slug(program), "host": host, "authed": False,
                "note": "site refused this session — paste a live login",
                "probes": len(probes)}
    return {"ok": True, "program": G._slug(program), "host": host, "authed": True,
            "note": "session accepted on this program's probe/surface",
            "probes": len(probes)}


def _host_apex(h):
    parts = [p for p in G._host_of(h).split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else G._host_of(h)


def auth_block(session, url):
    """Return the text to inject into a hunt task IF this session applies to url's host, else ''."""
    if not valid(session):
        return ""
    if _host_apex(session.get("host", "")) != _host_apex(url):
        return ""
    cookies = session.get("cookies") or {}
    headers = session.get("headers") or {}
    cstr = "; ".join(f"{k}={v}" for k, v in cookies.items()) if isinstance(cookies, dict) else str(cookies)
    hstr = " ".join(f"-H '{k}: {v}'" for k, v in headers.items()) if isinstance(headers, dict) else str(headers)
    return (
        "\nAUTHENTICATED SESSION AVAILABLE — you are logged in as a disposable TEST user "
        f"({session.get('user','test')}) on {session.get('host')}. Send requests with this session and test "
        "as a real logged-in user (IDOR on your own object IDs vs. a second test user, broken function-level "
        "authz, mass-assignment, business logic). Stay in-scope, read-only, no destructive actions.\n"
        + (f"  Cookie: {cstr}\n" if cstr else "")
        + (f"  Extra headers (curl): {hstr}\n" if hstr else "")
        + "  (If you need a SECOND account for IDOR victim IDs: `python3 " + ENGINE + "/identity.py new --program "
        + str(session.get("program", "")) + "`.)\n")


def _provision_task(program, host, ident, alt_hosts=None):
    e = ENGINE
    phone = (os.environ.get("HUNT_SIGNUP_PHONE") or "").strip()
    phone_line = ((f"PHONE: if a phone number is required anywhere, use {phone} (a real number the operator "
                   "controls). PREFER an email-based signup so you can read the verification code from the "
                   "mail.tm inbox (identity.py poll). If an SMS OTP to the phone is MANDATORY and you cannot "
                   "read it, do NOT hang \u2014 finish any email step and report notes='phone-otp-required'.\n")
                  if phone else "")
    alt = [h for h in (alt_hosts or []) if h and h != host]
    alt_line = ""
    if alt:
        alt_line = (
            f"IMPORTANT: {host} may have NO open self-service signup (it can be behind SSO / Cloudflare Access / "
            f"invite-only / be a pure API or storefront). If so, DON'T give up — try these other IN-SCOPE hosts "
            f"and register wherever an open registration actually exists: {', '.join(alt[:8])}. "
            f"Report the host you actually registered on.\n")
    return (
        f"AUTHORIZED bug-bounty test-account provisioning for program {program} — primary IN-SCOPE host {host}. "
        "Goal: create ONE disposable test account and capture a logged-in session. This is permitted test-account "
        "creation, not abuse — do it once, no bruteforce.\n"
        + alt_line +
        f"Identity to use (already has a live inbox): email={ident.get('email')} password={ident.get('password')} "
        f"first={ident.get('first')} last={ident.get('last')}.\n"
        + phone_line +
        "Steps:\n"
        f"1. Find the signup/registration flow on https://{host} (curl the page, locate the register endpoint+fields). "
        f"If none exists there, move on to one of the other in-scope hosts above.\n"
        "2. Register with the identity above. If a field is required you can't guess, use a sensible test value.\n"
        f"3. If it emails a verification link/code, read it: `python3 {e}/identity.py poll --program {program} "
        f"--email {ident.get('email')} --timeout 120` and complete verification.\n"
        "4. Log in and capture the authenticated session (the Set-Cookie session cookie(s), and any "
        "Authorization/bearer token the app uses for API calls).\n"
        "End with ONE fenced ```json``` object exactly: "
        '{"success":true|false,"host":"<host>","login_url":"<url>","cookies":{"name":"value"},'
        '"headers":{"Authorization":"Bearer ..."},"user":"<email>","notes":"<what happened / why if failed>"}. '
        "Only success:true if you actually logged in and have a working session cookie or token.")


def recent_attempt(program, base=DEFAULT_BASE, cooldown=21600):
    """True if we tried to provision recently — so a DOOMED signup (no open self-service registration) isn't
    re-attempted every round. But a TRANSIENT failure (agent timeout / rate-limit — the signup was still in
    progress, NOT proven impossible) uses a SHORT cooldown so we retry soon instead of locking out for hours."""
    s = load(program, base)
    if not s:
        return False
    cd = int(os.environ.get("HUNT_PROVISION_RETRY", "1800")) if s.get("transient") else cooldown
    return bool(time.time() - s.get("ts", 0) < cd)


def provision(program, base=DEFAULT_BASE, scope=None, host=None, timeout=None):
    """Provision an authenticated session. Guardrail-gated, single-shot (no retry), cooldown on failure.
    Returns session dict or {'error':...}. Signup is multi-step (find form -> register -> poll inbox ->
    verify -> login -> capture), so the default budget is generous and env-tunable (HUNT_PROVISION_TIMEOUT)."""
    if timeout is None:
        timeout = int(os.environ.get("HUNT_PROVISION_TIMEOUT", "600"))
    if scope is None:
        scope = G._load_scope(program, base)
    existing = load(program, base)
    if valid(existing):
        return existing                     # already have a working session — don't re-provision/clobber it
    host = host or pick_auth_host(scope)
    if not host:
        return {"error": "no in-scope auth host to register on"}
    # scope-gate only (don't audit — the identity mint below is the one countable account creation,
    # so a single provision consumes exactly ONE account slot, not two).
    ok, why = G.check(program, "register", url="https://" + host, scope=scope, base=base, log=False)
    if not ok:
        return {"error": why}
    ident = I.new_identity(program, base=base, scope=scope)
    if ident.get("error"):
        return {"error": "identity: " + ident["error"]}
    # single-shot: a long interactive signup must NOT be retried on timeout (that doubled the wait).
    # pass the other in-scope (non-third-party) hosts as fallbacks so a CF-Access/SSO-gated or signup-less
    # primary host doesn't waste the whole attempt — the agent registers wherever signup is actually open.
    alt_hosts = [G._host_of(h) for h in (scope or {}).get("in_scope", []) if "*" not in str(h)]
    alt_hosts = [h for h in alt_hosts if h and h != host and not _is_thirdparty(h)]
    r = A.run_agent(_provision_task(program, host, ident, alt_hosts=alt_hosts), timeout=timeout, attempts=1)
    if r.get("error"):
        # A missing JSON block is the agent failing to answer, not proof that signup is impossible.
        transient = r["error"] in ("timeout", "rate-limited", "parse:no-json") or str(r["error"]).startswith("parse")
        save(program, {"success": False, "program": G._slug(program), "host": host,
                       "error": "agent: " + r["error"], "transient": transient,
                       "ts": time.time()}, base=base)            # cooldown marker (short if transient)
        return {"error": "agent: " + r["error"], "host": host, "transient": transient}
    data = A.extract_json(r.get("result", "")) or {}
    if not isinstance(data, dict) or not data.get("success"):
        notes = (data.get("notes") if isinstance(data, dict) else "") or (r.get("result", "")[-300:])
        save(program, {"success": False, "program": G._slug(program), "host": host,
                       "error": "signup did not complete", "notes": notes, "ts": time.time()}, base=base)
        return {"error": "signup did not complete", "host": host, "notes": notes}
    session = {"success": True, "program": G._slug(program), "host": _clean_host(data.get("host", host)),
               "login_url": data.get("login_url", ""), "cookies": data.get("cookies") or {},
               "headers": data.get("headers") or {}, "user": data.get("user") or ident.get("email"),
               "notes": data.get("notes", ""), "ts": time.time(), "model": r.get("model")}
    save(program, session, base=base)
    G.audit(program, "login", valid(session), "session captured" if valid(session) else "no session",
            url="https://" + host, base=base)
    return session


# --------------------------------------------------------------------------- CLI
def _cmd_provision(a):
    s = provision(a.program, base=a.base)
    if s.get("error"):
        print("could not provision:", s["error"], "|", s.get("notes", ""), file=sys.stderr)
        return 3
    print(json.dumps({k: v for k, v in s.items() if k != "cookies"} |
                     {"cookies": {k: "***" for k in (s.get("cookies") or {})}}, indent=2))
    return 0


def _cmd_show(a):
    s = load(a.program, a.base)
    if not s:
        print("no session stored")
        return 1
    print(json.dumps({**s, "cookies": {k: "***" for k in (s.get("cookies") or {})}}, indent=2))
    return 0


def _cmd_selftest(_a):
    import tempfile
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "_targets"), exist_ok=True)
    json.dump({"name": "acme", "in_scope": ["*.acme.com", "sandbox-login.acme.com", "api.acme.com", "www.acme.com"],
               "self_register_ok": True},
              open(os.path.join(base, "_targets", "acme.json"), "w"))
    scope = G._load_scope("acme", base)

    # host preference: sandbox-login wins
    assert pick_auth_host(scope) == "sandbox-login.acme.com", pick_auth_host(scope)
    assert pick_auth_host({"in_scope": ["only.example.org"]}) == "only.example.org"
    assert pick_auth_host({"in_scope": ["*.x.com"]}) is None       # wildcard-only => nothing concrete

    # valid() + auth_block()
    assert valid({"success": True, "cookies": {"sid": "1"}})
    assert not valid({"success": True})
    assert not valid({"success": False, "cookies": {"a": "b"}})
    blk = auth_block({"success": True, "host": "sandbox-login.acme.com", "cookies": {"sid": "abc"},
                      "user": "t@x", "program": "acme"}, "https://sandbox-login.acme.com/account")
    assert "AUTHENTICATED SESSION" in blk and "sid=abc" in blk
    assert auth_block({"success": True, "host": "a.com", "cookies": {"x": "1"}},
                      "https://other.org/x") == ""              # host mismatch => no injection

    # vault round-trip
    save("acme", {"success": True, "host": "h", "cookies": {"s": "1"}}, base=base)
    assert load("acme", base)["host"] == "h"
    # a stored VALID session short-circuits provision (no re-provision / no clobber)
    assert provision("acme", base=base, scope=scope).get("host") == "h"
    os.remove(_vault("acme", base))        # clear it so the cap/provision paths below start clean

    # provision end-to-end with a MOCK agent (no network for signup) returning a canned session
    os.environ["HUNT_MOCK_AGENT"] = "1"
    os.environ["OPENCODE_HUNT_MODELS"] = "m1,m2"
    os.environ.pop("CURSOR_HUNT_MODELS", None)
    os.environ["HUNT_MOCK_RESULT"] = ('```json\n{"success":true,"host":"sandbox-login.acme.com",'
                                      '"login_url":"https://sandbox-login.acme.com/login","cookies":{"sid":"TESTSESSION"},'
                                      '"headers":{},"user":"t@acme","notes":"ok"}\n```')
    try:
        # identity.new_identity will try mail.tm (network); cap it out so provision fails cleanly if offline,
        # OR succeeds if online. Either way it must NOT raise. Force cap=0 to test the guardrail path first:
        os.environ["HUNT_MAX_ACCOUNTS"] = "0"
        r = provision("acme", base=base, scope=scope)
        assert r.get("error") and "cap" in r["error"], r         # cap hit => clean refusal
        # SUCCESS path: mock identity (no network) + mock agent returns a session -> stored + resumable
        os.environ["HUNT_MAX_ACCOUNTS"] = "3"
        _real_ni = I.new_identity
        I.new_identity = lambda program, base=None, scope=None: {
            "email": "t@acme", "password": "p", "first": "A", "last": "B", "username": "ab", "token": "tok"}
        try:
            ok = provision("acme", base=base, scope=scope)
            assert ok.get("success") and (ok.get("cookies") or {}).get("sid") == "TESTSESSION", ok
            assert valid(load("acme", base))                     # persisted + usable
            assert recent_attempt("acme", base)                  # cooldown marker set
            assert auth_block(load("acme", base), "https://api.acme.com/x")  # injectable into a hunt step
        finally:
            I.new_identity = _real_ni
    finally:
        for k in ("HUNT_MOCK_AGENT", "HUNT_MOCK_RESULT", "HUNT_MAX_ACCOUNTS", "OPENCODE_HUNT_MODELS", "CURSOR_HUNT_MODELS"):
            os.environ.pop(k, None)
    # hostile input never raises
    for bad in (None, "", 123, {"x": 1}):
        pick_auth_host(bad); valid(bad); auth_block(bad, bad)     # type: ignore
    c, h, _d = _extract_session([("X-Auth-Token", "tokentokentoken")],
                                b'{"api_key":"abcdefghijklmnop"}', {"sid": "1"})
    assert c.get("sid") == "1"
    assert h.get("X-Auth-Token") == "tokentokentoken" and h.get("api_key") == "abcdefghijklmnop"
    _c2, h2, _d2 = _extract_session([], b'{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}', {})
    assert h2.get("_token") == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sr = save_login("acme", "A", "sandbox-login.acme.com", "u@x", "pw",
                    "https://sandbox-login.acme.com/login", token_header="X-Auth-Token",
                    token_json_key="id", base=base)
    assert sr.get("ok") and load_creds("acme", base)["A"]["user"] == "u@x"
    assert load_creds("acme", base)["A"]["token_header"] == "X-Auth-Token"
    import base64 as _b64
    def _mkjwt(exp):
        p = _b64.urlsafe_b64encode(json.dumps({"exp": exp, "typ": "at+jwt", "aud": ["x"]}).encode()).decode().rstrip("=")
        return "eyJhbGciOiJub25lIn0." + p + ".sig"
    assert _jwt_expired_value("Bearer " + _mkjwt(int(time.time()) - 120))
    assert not _jwt_expired_value("Bearer " + _mkjwt(int(time.time()) + 3600))
    assert _bearer_from_cookies({"k": _mkjwt(int(time.time()) + 3600)})
    sr2 = save_login("acme", "B", "sandbox-login.acme.com", "v@x", "",
                     "https://sandbox-login.acme.com/refresh", cookies={"sid": "abc"},
                     method="GET", base=base)
    assert sr2.get("ok") and load_creds("acme", base)["B"]["cookies"]["sid"] == "abc"
    assert load_creds("acme", base)["B"]["method"] == "GET"
    raw = _request("https://example.com/x", headers={"X-Auth-Token": "abc"})
    assert raw.headers.get("X-Auth-Token") == "abc"
    print("authsession.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="authenticated test-session provisioner (guardrail-gated)")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("provision"); pp.add_argument("--program", required=True); pp.set_defaults(fn=_cmd_provision)
    ps = sub.add_parser("show"); ps.add_argument("--program", required=True); ps.set_defaults(fn=_cmd_show)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
