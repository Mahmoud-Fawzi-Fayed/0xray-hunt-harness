#!/usr/bin/env python3
"""
identity.py — disposable test identities for authorized authenticated testing. When a target needs an
account to reach the interesting surface (IDOR needs user A and user B, auth bugs need a session), this
mints a throwaway identity backed by a real, pollable inbox (mail.tm, free, no key) so the agent can
click the verification link and log in — all inside the guardrails (scope + per-program account cap).

  new_identity(program)        -> {email,password,first,last,username,token,provider}  (mail.tm mailbox)
  wait_for(token, ...)         -> first inbox message matching a sender/subject pattern
  extract_code / extract_link  -> pull the OTP or verification URL out of a message body
  saved(program) / save(...)   -> the per-program vault of issued identities (chmod 600)

Every mint goes through guardrails.check(program,'identity'): it refuses once the program's account cap
is hit, and it records the action to the audit trail. Network calls are best-effort and never raise
into the hunt loop.

CLI:
  python3 engine/identity.py new  --program paddle
  python3 engine/identity.py poll --program paddle --email <addr> --timeout 90
  python3 engine/identity.py list --program paddle
  python3 engine/identity.py selftest     # offline: field gen + code/link extraction
"""
import argparse
import json
import os
import random
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.request

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import guardrails as G  # noqa: E402

MAILTM = "https://api.mail.tm"
UA = "Mozilla/5.0 (X11; Linux x86_64) hunt-harness/identity"
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

_FIRST = ["alex", "sam", "jordan", "taylor", "casey", "morgan", "riley", "jamie", "drew", "quinn",
          "avery", "parker", "reese", "skyler", "rowan", "emerson", "hayden", "noel"]
_LAST = ["carter", "reed", "blake", "nolan", "shaw", "frost", "lane", "pierce", "vance", "hale",
         "mercer", "sloan", "bishop", "rhodes", "wells", "dalton", "york", "cole"]
_OTP_RE = re.compile(r"\b(\d{4,8})\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


def _host_of(u):
    return G._host_of(u)


def gen_fields():
    """Pure, offline: a realistic-looking identity (no network)."""
    first = random.choice(_FIRST)
    last = random.choice(_LAST)
    tag = secrets.token_hex(3)
    username = f"{first}{last}{tag}"          # no dots/symbols: some providers normalize them away
    # strong password: upper+lower+digit+symbol, no ambiguous chars
    pool = string.ascii_letters + string.digits + "!@#$%^&*-_"
    pw = "".join(secrets.choice(pool) for _ in range(16))
    pw = "A" + pw + "a9!"                       # guarantee all classes present
    return {"first": first.capitalize(), "last": last.capitalize(), "username": username, "password": pw}


def extract_code(text):
    """First 4-8 digit numeric code in a message body, or None."""
    m = _OTP_RE.search(str(text or ""))
    return m.group(1) if m else None


def extract_link(text, host_hint=None):
    """First verification-looking URL (optionally whose host contains host_hint), or None."""
    urls = _URL_RE.findall(str(text or ""))
    if host_hint:
        hh = str(host_hint).lower()
        for u in urls:
            if hh in _host_of(u):
                return u
    # prefer links that look like verification/confirm/activate
    for u in urls:
        if re.search(r"verif|confirm|activate|validate|token|magic", u, re.I):
            return u
    return urls[0] if urls else None


# --------------------------------------------------------------------------- mail.tm (network)
def _api(method, path, token=None, data=None, timeout=20):
    headers = {"User-Agent": UA, "Accept": "application/json"}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(MAILTM + path, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "replace")
    return json.loads(raw) if raw else {}


def _members(d):
    """mail.tm responses come as a bare list OR {'hydra:member':[...]} OR {'member':[...]}."""
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        return d.get("hydra:member") or d.get("member") or []
    return []


def _domain():
    items = _members(_api("GET", "/domains"))
    for it in items:
        if isinstance(it, dict) and it.get("isActive", True) and it.get("domain"):
            return it["domain"]
    return items[0]["domain"] if items and isinstance(items[0], dict) else None


def token_for(email, password, timeout=20):
    try:
        return (_api("POST", "/token", data={"address": email, "password": password}, timeout=timeout) or {}).get("token")
    except Exception:  # noqa: BLE001
        return None


def new_identity(program, base=DEFAULT_BASE, scope=None):
    """Mint a disposable identity with a live mailbox. Returns dict or {'error':...}. Guardrail-gated."""
    ok, why = G.check(program, "identity", scope=scope, base=base)
    if not ok:
        return {"error": why}
    f = gen_fields()
    try:
        dom = _domain()
        if not dom:
            return {"error": "mail.tm: no domain available"}
        email = f"{f['username']}@{dom}"
        acct = _api("POST", "/accounts", data={"address": email, "password": f["password"]})
        if isinstance(acct, dict) and acct.get("address"):
            email = acct["address"]                        # trust the canonical address the API assigned
        tok = None
        for delay in (0.8, 1.5, 3.0):                     # mail.tm needs a beat before /token works
            time.sleep(delay)
            tok = token_for(email, f["password"])
            if tok:
                break
        ident = {"program": G._slug(program), "email": email, "password": f["password"],
                 "first": f["first"], "last": f["last"], "username": f["username"],
                 "token": tok, "provider": "mail.tm", "ts": time.time()}
        save(program, ident, base=base)
        return ident
    except urllib.error.HTTPError as e:
        return {"error": f"mail.tm HTTP {e.code}: {e.read()[:200].decode('utf-8','replace')}"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def messages(token, timeout=20):
    try:
        return _members(_api("GET", "/messages", token=token, timeout=timeout))
    except Exception:  # noqa: BLE001
        return []


def _message(token, mid, timeout=20):
    try:
        return _api("GET", "/messages/" + str(mid), token=token, timeout=timeout)
    except Exception:  # noqa: BLE001
        return {}


def wait_for(token, timeout=120, sender=None, subject=None, poll=5):
    """Poll the inbox until a matching message arrives. Returns {subject,from,text,html,code,link} or {}."""
    if not token:
        return {}
    deadline = time.time() + max(5, int(timeout))
    while time.time() < deadline:
        for m in messages(token):
            frm = ((m.get("from") or {}).get("address") or "") if isinstance(m.get("from"), dict) else str(m.get("from") or "")
            subj = m.get("subject") or ""
            if sender and sender.lower() not in frm.lower():
                continue
            if subject and subject.lower() not in subj.lower():
                continue
            full = _message(token, m.get("id"))
            text = full.get("text") or ""
            htmls = full.get("html") or []
            html = "\n".join(htmls) if isinstance(htmls, list) else str(htmls)
            blob = text + "\n" + html
            return {"subject": subj, "from": frm, "text": text, "html": html,
                    "code": extract_code(blob), "link": extract_link(blob)}
        time.sleep(max(2, int(poll)))
    return {}


# --------------------------------------------------------------------------- vault (chmod 600)
def _vault(program, base):
    d = os.path.join(os.path.expanduser(base), "_identity")
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return os.path.join(d, G._slug(program) + ".json")


def saved(program, base=DEFAULT_BASE):
    try:
        return json.load(open(_vault(program, base)))
    except (OSError, json.JSONDecodeError):
        return []


def save(program, ident, base=DEFAULT_BASE):
    path = _vault(program, base)
    cur = saved(program, base)
    cur.append(ident)
    json.dump(cur, open(path, "w"), indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


# --------------------------------------------------------------------------- CLI
def _cmd_new(a):
    ident = new_identity(a.program, base=a.base)
    if ident.get("error"):
        print("refused/failed:", ident["error"], file=sys.stderr)
        return 3
    print(json.dumps({k: v for k, v in ident.items() if k != "password"} | {"password": "***stored***"}, indent=2))
    print(f"(credentials saved to {_vault(a.program, a.base)}, chmod 600)", file=sys.stderr)
    return 0


def _cmd_poll(a):
    vault = {i.get("email"): i for i in saved(a.program, a.base)}
    ident = vault.get(a.email)
    if not ident or not ident.get("token"):
        print("no saved identity/token for that email", file=sys.stderr)
        return 1
    res = wait_for(ident["token"], timeout=a.timeout, sender=a.sender, subject=a.subject)
    print(json.dumps(res, indent=2) if res else "(no matching message before timeout)")
    return 0 if res else 1


def _cmd_list(a):
    for i in saved(a.program, a.base):
        print(f"  {i.get('email'):42.42s} token={'yes' if i.get('token') else 'no'}  {i.get('first')} {i.get('last')}")
    return 0


def _cmd_selftest(_a):
    # field generation is strong + well-formed
    f = gen_fields()
    assert all(f[k] for k in ("first", "last", "username", "password"))
    pw = f["password"]
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
    assert any(c in "!@#$%^&*-_" for c in pw) and len(pw) >= 12
    assert len({gen_fields()["username"] for _ in range(50)}) > 40     # high entropy, few collisions

    # code + link extraction
    body = "Your code is 834192. Confirm: https://api.acme.com/verify?token=abc123 thanks"
    assert extract_code(body) == "834192"
    assert extract_link(body) == "https://api.acme.com/verify?token=abc123"
    assert extract_link(body, host_hint="api.acme.com").startswith("https://api.acme.com")
    assert extract_link("no links here") is None and extract_code("no digits") is None

    # hostile input never raises
    for bad in (None, "", 123, {"x": 1}, ["a"]):
        extract_code(bad); extract_link(bad)                          # type: ignore
    assert messages(None) == [] and token_for(None, None) is None     # offline-safe

    # vault round-trips and guardrail cap is honored without network
    import tempfile
    base = tempfile.mkdtemp()
    save("p", {"email": "a@b.c", "token": "t"}, base=base)
    assert saved("p", base)[0]["email"] == "a@b.c"
    os.makedirs(os.path.join(base, "_targets"), exist_ok=True)
    json.dump({"name": "p", "in_scope": ["*.example.com"], "self_register_ok": True},
              open(os.path.join(base, "_targets", "p.json"), "w"))
    os.environ["HUNT_MAX_ACCOUNTS"] = "0"
    r = new_identity("p", base=base)                                  # cap 0 => refused before any network
    assert r.get("error") and "cap" in r["error"], r
    os.environ.pop("HUNT_MAX_ACCOUNTS", None)
    print("identity.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="disposable test identities (mail.tm)")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pn = sub.add_parser("new"); pn.add_argument("--program", required=True); pn.set_defaults(fn=_cmd_new)
    pp = sub.add_parser("poll"); pp.add_argument("--program", required=True); pp.add_argument("--email", required=True)
    pp.add_argument("--sender", default=None); pp.add_argument("--subject", default=None)
    pp.add_argument("--timeout", type=int, default=120); pp.set_defaults(fn=_cmd_poll)
    pl = sub.add_parser("list"); pl.add_argument("--program", required=True); pl.set_defaults(fn=_cmd_list)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
