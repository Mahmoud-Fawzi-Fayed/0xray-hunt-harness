#!/usr/bin/env python3
"""
sms.py — phone-number + SMS-OTP for targets that gate signup behind phone verification. Provider-
agnostic: you bring an account at a reputable SMS-verification provider and set two env vars; the
harness rents a number, waits for the one-time code, and releases the number. There is no keyless
option — every usable SMS provider is paid — so without SMS_PROVIDER + SMS_API_KEY this module is
cleanly DISABLED and the hunt simply skips phone-gated flows instead of failing.

Supported (REST, no SDK):
  5sim        SMS_PROVIDER=5sim        SMS_API_KEY=<bearer>         (default country=any, product per-call)
  sms-activate SMS_PROVIDER=sms-activate SMS_API_KEY=<key>

Config (via env / harness .env):
  SMS_PROVIDER   5sim | sms-activate          (unset => disabled)
  SMS_API_KEY    provider API key / bearer
  SMS_COUNTRY    provider country code/name (default: provider default)

API:
  enabled()                         -> bool
  get_number(service, program)      -> {id, phone, provider} | {error}
  wait_sms(order_id, timeout)       -> {code, text} | {}
  finish(order_id) / cancel(order_id)

Every rental is routed through guardrails.check(program,'sms') and audited. Network calls never raise
into the hunt loop. This is for verifying YOUR OWN test account on an in-scope, authorized target —
not for defeating a victim's 2FA.

CLI:
  python3 engine/sms.py status
  python3 engine/sms.py number --service paddle --program paddle
  python3 engine/sms.py wait --order <id> --timeout 120
  python3 engine/sms.py selftest       # offline: disabled-state + code parse
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import guardrails as G  # noqa: E402
try:
    import notify as N   # reuse the .env loader so SMS_* get picked up like SMTP_*
except Exception:        # noqa: BLE001
    N = None

UA = "Mozilla/5.0 hunt-harness/sms"
_OTP_RE = re.compile(r"\b(\d{4,8})\b")


def _env(k, d=""):
    if N is not None:
        try:
            N._load_env_file()
        except Exception:  # noqa: BLE001
            pass
    return os.environ.get(k, d)


def provider():
    return (_env("SMS_PROVIDER", "") or "").strip().lower()


def enabled():
    return bool(provider() and _env("SMS_API_KEY", ""))


def status():
    return {"enabled": enabled(), "provider": provider() or None,
            "country": _env("SMS_COUNTRY", "") or None,
            "note": "set SMS_PROVIDER + SMS_API_KEY to enable phone-gated signups"}


def extract_code(text):
    m = _OTP_RE.search(str(text or ""))
    return m.group(1) if m else None


def _get(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# ------------------------------------------------------------------ provider: 5sim
def _5sim_number(service, country):
    key = _env("SMS_API_KEY")
    country = country or "any"
    url = f"https://5sim.net/v1/user/buy/activation/{urllib.parse.quote(country)}/any/{urllib.parse.quote(service)}"
    d = json.loads(_get(url, headers={"Authorization": "Bearer " + key, "Accept": "application/json"}))
    return {"id": str(d.get("id")), "phone": d.get("phone"), "provider": "5sim"}


def _5sim_check(order_id):
    key = _env("SMS_API_KEY")
    d = json.loads(_get(f"https://5sim.net/v1/user/check/{order_id}",
                        headers={"Authorization": "Bearer " + key, "Accept": "application/json"}))
    for s in d.get("sms") or []:
        code = s.get("code") or extract_code(s.get("text"))
        if code:
            return {"code": code, "text": s.get("text", "")}
    return {}


def _5sim_finish(order_id, action="finish"):
    key = _env("SMS_API_KEY")
    try:
        _get(f"https://5sim.net/v1/user/{action}/{order_id}",
             headers={"Authorization": "Bearer " + key, "Accept": "application/json"})
        return True
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------------ provider: sms-activate
def _sa_base(**params):
    key = _env("SMS_API_KEY")
    q = urllib.parse.urlencode({"api_key": key, **params})
    return _get("https://api.sms-activate.org/stubs/handler_api.php?" + q)


def _sa_number(service, country):
    r = _sa_base(action="getNumber", service=service, country=country or "0")
    # "ACCESS_NUMBER:<id>:<phone>"
    parts = r.split(":")
    if parts and parts[0] == "ACCESS_NUMBER" and len(parts) >= 3:
        return {"id": parts[1], "phone": parts[2], "provider": "sms-activate"}
    return {"error": f"sms-activate: {r[:120]}"}


def _sa_check(order_id):
    r = _sa_base(action="getStatus", id=order_id)
    if r.startswith("STATUS_OK:"):
        text = r.split(":", 1)[1]
        return {"code": extract_code(text), "text": text}
    return {}


def _sa_finish(order_id, status_code=6):
    try:
        _sa_base(action="setStatus", id=order_id, status=status_code)   # 6=finish, 8=cancel
        return True
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------------ public API
def get_number(service, program, country=None, base=None, scope=None):
    if not enabled():
        return {"error": "SMS disabled (set SMS_PROVIDER + SMS_API_KEY)"}
    ok, why = G.check(program, "sms", scope=scope, base=base)
    if not ok:
        return {"error": why}
    country = country or (_env("SMS_COUNTRY") or None)
    try:
        if provider() == "5sim":
            r = _5sim_number(service, country)
        elif provider() == "sms-activate":
            r = _sa_number(service, country)
        else:
            return {"error": f"unknown SMS_PROVIDER {provider()!r} (supported: 5sim, sms-activate)"}
        G.audit(program, "sms-number", not r.get("error"), r.get("error") or "rented", extra={"phone": r.get("phone")}, base=base)
        return r
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def wait_sms(order_id, timeout=180, poll=6):
    if not enabled() or not order_id:
        return {}
    deadline = time.time() + max(10, int(timeout))
    checker = _5sim_check if provider() == "5sim" else _sa_check if provider() == "sms-activate" else None
    if checker is None:
        return {}
    while time.time() < deadline:
        try:
            r = checker(order_id)
        except Exception:  # noqa: BLE001
            r = {}
        if r.get("code"):
            return r
        time.sleep(max(3, int(poll)))
    return {}


def finish(order_id):
    if provider() == "5sim":
        return _5sim_finish(order_id, "finish")
    if provider() == "sms-activate":
        return _sa_finish(order_id, 6)
    return False


def cancel(order_id):
    if provider() == "5sim":
        return _5sim_finish(order_id, "cancel")
    if provider() == "sms-activate":
        return _sa_finish(order_id, 8)
    return False


# --------------------------------------------------------------------------- CLI
def _cmd_status(_a):
    print(json.dumps(status(), indent=2))
    return 0


def _cmd_number(a):
    r = get_number(a.service, a.program, country=a.country, base=a.base)
    print(json.dumps(r, indent=2))
    return 0 if not r.get("error") else 3


def _cmd_wait(a):
    r = wait_sms(a.order, timeout=a.timeout)
    print(json.dumps(r, indent=2) if r else "(no SMS before timeout / disabled)")
    return 0 if r else 1


def _cmd_selftest(_a):
    # DISABLED unless configured — this is the safe default
    saved = {k: os.environ.pop(k, None) for k in ("SMS_PROVIDER", "SMS_API_KEY")}
    if N is not None:
        os.environ["HUNT_ENV_FILE"] = "/nonexistent-selftest-env"
        N._ENV_LOADED = False
    try:
        assert enabled() is False
        assert get_number("svc", "p")["error"].startswith("SMS disabled")
        assert wait_sms("x") == {} and finish("x") is False and cancel("x") is False
        st = status(); assert st["enabled"] is False and "SMS_PROVIDER" in st["note"]
        # code extraction + hostile input
        assert extract_code("Your Paddle code is 55213.") == "55213"
        for bad in (None, "", 123, {"a": 1}):
            extract_code(bad)                       # type: ignore
        # with a (fake) key it reports enabled but unknown provider errors cleanly
        os.environ["SMS_PROVIDER"] = "nope"; os.environ["SMS_API_KEY"] = "k"
        if N is not None:
            N._ENV_LOADED = True                    # don't let .env overwrite our fake values
        assert enabled() is True
        assert "unknown SMS_PROVIDER" in get_number("s", "p")["error"]
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
    print("sms.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="provider-agnostic SMS-OTP for phone-gated signups")
    ap.add_argument("--base", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=_cmd_status)
    pn = sub.add_parser("number"); pn.add_argument("--service", required=True); pn.add_argument("--program", required=True)
    pn.add_argument("--country", default=None); pn.set_defaults(fn=_cmd_number)
    pw = sub.add_parser("wait"); pw.add_argument("--order", required=True); pw.add_argument("--timeout", type=int, default=180)
    pw.set_defaults(fn=_cmd_wait)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
