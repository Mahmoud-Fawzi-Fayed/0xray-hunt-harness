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


def _is_thirdparty(host):
    h = G._host_of(host)
    apex = ".".join(h.split(".")[-2:]) if h.count(".") >= 1 else h
    return h in THIRDPARTY_APEX or apex in THIRDPARTY_APEX


def _apex(h):
    return G._host_of(h)


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
                   headers=hdrs or None, base=base)
    except Exception:  # noqa: BLE001
        pass


def valid(session):
    """A session is usable if it carries at least one cookie or an auth header."""
    if not isinstance(session, dict) or not session.get("success"):
        return False
    return bool(session.get("cookies")) or bool(session.get("headers"))


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


def set_manual(program, host, cookie=None, headers=None, token=None, user=None, base=DEFAULT_BASE, ident="A"):
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
    if ident == "B":
        # a SECOND account for cross-account IDOR/BOLA (the victim). Store ONLY as authn 'B' — don't
        # replace the agent's primary session (A) or requeue the surface; the agent reaches B via
        # `netget --as B` / `authz.py diff` to prove A-reads-B's-data.
        _mirror_to_authn(program, sess, base, ident="B")
        return {"ok": True, "program": slug, "host": host, "ident": "B", "cookies": len(cookies),
                "headers": list(hdrs.keys()), "user": sess["user"], "requeued": 0}
    save(program, sess, base=base)
    # make the login immediately productive: clear the tested-state so the hunt RE-COVERS its surface
    # AUTHENTICATED now, instead of waiting out the 48h re-hunt window on already-tested (unauth) items.
    requeued = 0
    try:
        sp = os.path.join(os.path.expanduser(base), slug, "state.json")
        stt = json.load(open(sp))
        requeued = len(stt.get("tested") or [])
        stt["tested"] = {}
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
    """Live probe: fetch the session's host WITH and WITHOUT the stored cookies and compare, to tell whether
    the target actually ACCEPTS the login (vs expired/rejected). Best-effort heuristic; returns a verdict."""
    import urllib.request
    import urllib.error
    s = load(program, base)
    if not valid(s):
        return {"ok": False, "error": "no valid session stored for this program"}
    host = G._host_of(s.get("host", ""))
    if not host:
        return {"ok": False, "error": "stored session has no host"}
    url = "https://" + host + "/"
    cstr = "; ".join(f"{k}={v}" for k, v in (s.get("cookies") or {}).items())
    extra = dict(s.get("headers") or {})
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"

    def fetch(auth):
        h = {"User-Agent": ua, "Accept": "text/html,application/json"}
        if auth:
            if cstr:
                h["Cookie"] = cstr
            h.update(extra)
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout)
            body = r.read(300000)
            return {"status": getattr(r, "status", r.getcode()), "final": r.geturl(),
                    "len": len(body), "body": body.decode("utf-8", "ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "final": url, "len": 0, "body": ""}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)[:120]}

    a = fetch(True)
    if a.get("error"):
        return {"ok": False, "error": "could not reach " + host + ": " + a["error"]}
    n = fetch(False)
    af = (a.get("final") or "").lower()
    body = a.get("body", "").lower()
    markers = ["logout", "log out", "my profile", "account-manager", '"isloggedin":true',
               'data-logged-in="true"', "karma", "/settings", "loggedin\":true"]
    authed, note = None, ""
    if any(k in af for k in ("login", "signin", "sign-in")):
        authed, note = False, "the session request was redirected to a login page — session rejected/expired"
    elif n.get("status") in (401, 403) and a.get("status") == 200:
        authed, note = True, "authenticated request returns 200 while anonymous is blocked (401/403)"
    elif any(m in body for m in markers):
        authed, note = True, "logged-in markers present in the response (logout / profile / settings / karma)"
    elif a.get("len") and n.get("len") and abs(a["len"] - n["len"]) > 3000:
        authed, note = True, "authenticated response is materially different from anonymous (personalized)"
    else:
        authed, note = None, ("couldn't confirm from the homepage — the hunt still tries the session; "
                              "check the hunt log for the 'AUTHENTICATED' line")
    return {"ok": True, "program": G._slug(program), "host": host, "authed": authed, "note": note,
            "with_session": {k: a.get(k) for k in ("status", "final", "len")},
            "anonymous": {k: n.get(k) for k in ("status", "final", "len")}}


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
        transient = r["error"] in ("timeout", "rate-limited")   # still-in-progress, not a proven dead-end
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
    session = {"success": True, "program": G._slug(program), "host": data.get("host", host),
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
    json.dump({"name": "acme", "in_scope": ["*.acme.com", "sandbox-login.acme.com", "api.acme.com", "www.acme.com"]},
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
    os.environ["CURSOR_HUNT_MODELS"] = "m1,m2"
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
        for k in ("HUNT_MOCK_AGENT", "HUNT_MOCK_RESULT", "HUNT_MAX_ACCOUNTS"):
            os.environ.pop(k, None)
    # hostile input never raises
    for bad in (None, "", 123, {"x": 1}):
        pick_auth_host(bad); valid(bad); auth_block(bad, bad)     # type: ignore
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
