#!/usr/bin/env python3
"""
guardrails.py — the safety gate every "write" capability (account creation, temp-mail, SMS, login
attempts) must pass before it runs. Hunting itself is read-only; this module exists so the autonomous
parts that *do* touch a target (registering a test account, requesting an SMS OTP) stay inside the
rules of an authorized engagement and can never drift into abuse.

What it enforces:
  - SCOPE          an action's host must be in the program's in_scope (wildcard-aware) and not
                   out_of_scope. Out-of-scope => hard refuse.
  - SELF-REGISTER  per-target `self_register_ok` (default True for in-scope hosts) lets you turn
                   account creation off for a program whose rules forbid it.
  - ACCOUNT CAP    at most HUNT_MAX_ACCOUNTS (default 3) test accounts per program — enough for
                   A/B/C multi-user testing (IDOR, auth), never a farm.
  - NO BRUTEFORCE  password / OTP / token brute loops are refused outright (workspace rule).
  - AUDIT          every allowed or refused write action is appended to an audit log you can review.

Everything is best-effort and never raises into the hunt loop: a refusal returns (False, reason).

CLI:
  python3 engine/guardrails.py check --program paddle --url https://api.paddle.com/signup --action register
  python3 engine/guardrails.py audit --program paddle
  python3 engine/guardrails.py selftest
"""
import argparse
import datetime
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # import the canonical scope matcher

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# actions that are never allowed, regardless of scope — the harness does not brute-force (workspace rule)
BRUTE_ACTIONS = {"bruteforce", "password-spray", "credential-stuffing", "otp-brute", "token-brute"}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _base(base=None):
    return os.path.expanduser(base or DEFAULT_BASE)


def _slug(p):
    return re.sub(r"[^a-z0-9._-]+", "-", str(p or "").strip().lower()).strip("-") or "unknown"


def _host_of(u):
    u = str(u or "").strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)
    return u.split("/")[0].split("?")[0].split("#")[0].split("@")[-1].split(":")[0].lower()


def _host_matches(host, pattern):
    """host matches an in_scope/out_of_scope pattern, honoring a leading wildcard (*.paddle.com)."""
    host = (host or "").lower()
    p = _host_of(pattern) if "://" in str(pattern) else str(pattern or "").lstrip(".").lower()
    if not host or not p:
        return False
    if p.startswith("*."):
        suf = p[1:]                       # ".paddle.com"
        return host == p[2:] or host.endswith(suf)
    if p.startswith("*"):
        return host.endswith(p.lstrip("*").lstrip("."))
    return host == p


def _norm_scope_pattern(p):
    """Reduce a URL-form pattern to its host; leave host / *.host / CIDR / re: patterns intact so the
    canonical scope.Scope matcher gets exactly the forms it understands."""
    p = str(p or "").strip()
    if not p or p.startswith("re:"):
        return p
    if "://" in p:
        return _host_of(p)
    return p


def in_scope(url, scope):
    """True iff url's host is in scope. Delegates to the engine's canonical scope.Scope matcher so the
    write-gate (register/login/SMS) and the hunt-gate agree EXACTLY — same CIDR / re: / wildcard /
    suffix-confusion semantics, one source of truth. Falls back to a local deny-wins matcher only if
    the import fails (never crashes the gate)."""
    host = _host_of(url)
    if not host:
        return False
    s = scope or {}
    ins = s.get("in_scope") or []
    if not ins:                            # no scope loaded => cannot assert in-scope => refuse writes
        return False
    try:
        import scope as _scope_mod
        ins_n = [_norm_scope_pattern(p) for p in ins]
        oos_n = [_norm_scope_pattern(p) for p in (s.get("out_of_scope") or [])]
        return _scope_mod.Scope(ins_n, oos_n).in_scope_host(url)
    except Exception:                      # fallback: local matcher (deny-wins), never break the gate
        for bad in s.get("out_of_scope") or []:
            if _host_matches(host, bad):
                return False
        return any(_host_matches(host, g) for g in ins)


def max_accounts():
    try:
        return max(0, int(os.environ.get("HUNT_MAX_ACCOUNTS", "3")))
    except ValueError:
        return 3


def _audit_path(base):
    d = os.path.join(_base(base), "_audit")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "actions.jsonl")


def audit(program, action, allowed, reason, url=None, extra=None, base=None):
    """Append one decision to the audit log. Never raises."""
    rec = {"ts": _now(), "program": _slug(program), "action": action, "allowed": bool(allowed),
           "reason": reason, "url": url}
    if extra:
        rec["extra"] = extra
    try:
        with open(_audit_path(base), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass
    return rec


def read_audit(program=None, n=200, base=None):
    out = []
    try:
        for line in open(_audit_path(base), encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if program and r.get("program") != _slug(program):
                continue
            out.append(r)
    except OSError:
        pass
    return out[-max(1, min(int(n or 200), 2000)):]


def account_count(program, base=None):
    """How many test accounts we've already provisioned for this program (from the audit trail)."""
    return sum(1 for r in read_audit(program, n=2000, base=base)
               if r.get("action") in ("register", "identity") and r.get("allowed"))


def _load_scope(program, base):
    path = os.path.join(_base(base), "_targets", _slug(program) + ".json")
    try:
        return json.load(open(path))
    except (OSError, json.JSONDecodeError):
        return None


def check(program, action, url=None, scope=None, base=None, log=True):
    """The one call every write-capability makes. Returns (allowed: bool, reason: str).

    action: 'register' | 'identity' | 'tempmail' | 'sms' | 'login' | <brute*> | other
    """
    action = str(action or "").strip().lower()
    scope = scope if scope is not None else _load_scope(program, base)

    if action in BRUTE_ACTIONS:
        reason = "refused: bruteforce/cracking is disabled by policy (enumerate the intended path instead)"
        if log:
            audit(program, action, False, reason, url, base=base)
        return False, reason

    # scope-bearing actions must target an in-scope host
    if action in ("register", "login", "tempmail-verify") and url is not None:
        if not in_scope(url, scope):
            reason = f"refused: {_host_of(url)!r} is not in-scope for {program!r} (or no scope loaded)"
            if log:
                audit(program, action, False, reason, url, base=base)
            return False, reason

    if action in ("register", "identity"):
        if scope is not None and scope.get("self_register_ok") is False:
            reason = f"refused: self-registration disabled for {program!r} (program rules)"
            if log:
                audit(program, action, False, reason, url, base=base)
            return False, reason
        used, cap = account_count(program, base), max_accounts()
        if used >= cap:
            reason = f"refused: account cap reached for {program!r} ({used}/{cap}) — raise HUNT_MAX_ACCOUNTS if needed"
            if log:
                audit(program, action, False, reason, url, base=base)
            return False, reason

    reason = "allowed"
    if log:
        audit(program, action, True, reason, url, base=base)
    return True, reason


# --------------------------------------------------------------------------- CLI
def _cmd_check(a):
    ok, why = check(a.program, a.action, url=a.url, base=a.base, log=not a.dry)
    print(json.dumps({"allowed": ok, "reason": why,
                      "accounts": account_count(a.program, a.base), "cap": max_accounts()}, indent=2))
    return 0 if ok else 3


def _cmd_audit(a):
    for r in read_audit(a.program, n=a.n, base=a.base):
        mark = "ALLOW" if r.get("allowed") else "REFUSE"
        print(f"  {r.get('ts','')[:19]}  [{mark:6}] {r.get('program')}/{r.get('action')}: {r.get('reason')}")
    return 0


def _cmd_selftest(_a):
    import tempfile
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "_targets"), exist_ok=True)
    json.dump({"name": "acme", "in_scope": ["*.acme.com", "https://api.acme.com"],
               "out_of_scope": ["admin.acme.com"]},
              open(os.path.join(base, "_targets", "acme.json"), "w"))

    # scope matching
    assert in_scope("https://api.acme.com/x", _load_scope("acme", base))
    assert in_scope("https://foo.acme.com", _load_scope("acme", base))
    assert not in_scope("https://admin.acme.com", _load_scope("acme", base))  # excluded
    assert not in_scope("https://evil.com", _load_scope("acme", base))        # not listed
    assert not in_scope("https://evil.com", None)                             # no scope => refuse

    # bruteforce always refused
    ok, why = check("acme", "otp-brute", base=base)
    assert not ok and "bruteforce" in why, why

    # out-of-scope register refused
    ok, _ = check("acme", "register", url="https://evil.com/signup", base=base)
    assert not ok
    # in-scope register allowed, then capped
    os.environ["HUNT_MAX_ACCOUNTS"] = "2"
    assert check("acme", "register", url="https://api.acme.com/signup", base=base)[0]
    assert check("acme", "register", url="https://api.acme.com/signup", base=base)[0]
    ok, why = check("acme", "register", url="https://api.acme.com/signup", base=base)
    assert not ok and "cap" in why, why
    assert account_count("acme", base) == 2

    # self_register_ok=False disables it
    json.dump({"name": "noreg", "in_scope": ["*.noreg.com"], "self_register_ok": False},
              open(os.path.join(base, "_targets", "noreg.json"), "w"))
    ok, why = check("noreg", "register", url="https://a.noreg.com/s", base=base)
    assert not ok and "disabled" in why, why

    # hostile input never raises
    for bad in (None, "", 123, {"x": 1}):
        check("p", bad, url=bad, base=base)  # type: ignore
        _host_of(bad)                        # type: ignore
    os.environ.pop("HUNT_MAX_ACCOUNTS", None)
    print("guardrails.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="write-capability safety gate")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check")
    pc.add_argument("--program", required=True)
    pc.add_argument("--action", required=True)
    pc.add_argument("--url", default=None)
    pc.add_argument("--dry", action="store_true", help="don't write to the audit log")
    pc.set_defaults(fn=_cmd_check)
    pa = sub.add_parser("audit")
    pa.add_argument("--program", default=None)
    pa.add_argument("--n", type=int, default=200)
    pa.set_defaults(fn=_cmd_audit)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
