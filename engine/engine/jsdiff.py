#!/usr/bin/env python3
"""
jsdiff.py — turn a redeployed JS bundle into a hunt list.

When novelty.py flags a `changed_js` (a bundle's hash moved) or a `new_js`, that redeploy almost
always ships new code — new API routes, new parameters, sometimes a leaked key — that NOBODY has
hunted yet. Being first on it is the cleanest way to avoid duplicates. This tool diffs the old and
new bundle text and surfaces ONLY what's new, so you hunt the delta instead of re-reading the whole
app.

Extracts + diffs four things from JS text:
  - endpoints : relative API paths ("/api/v2/...") and absolute URLs
  - params    : query-string parameter names and obvious request-body field names
  - secrets   : high-confidence key/token patterns (AWS, Google, Slack, GitHub, JWT, generic api_key=)
  - routes    : path-like string literals (client routes, templates) not already counted as endpoints

stdlib only, OFFLINE (diffs text you give it). A `fetch` helper uses curl only when you ask for URLs.

CLI:
  python3 engine/jsdiff.py diff  --old old.js --new new.js [--json]
  python3 engine/jsdiff.py fetch --old <OLD_URL> --new <NEW_URL> [--json]   # curl both, then diff
  python3 engine/jsdiff.py scan  --new new.js [--json]                      # extract from one file (no diff)
  python3 engine/jsdiff.py selftest
"""
import argparse
import json
import re
import subprocess
import sys

# --- string-literal extraction -------------------------------------------------
_STR = re.compile(r"""["'`]([^"'`\n\r]{2,256})["'`]""")
_ABS_URL = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}""")
_REL_PATH = re.compile(r"^/[A-Za-z0-9_][A-Za-z0-9_\-./{}:]{1,}$")
_API_HINT = re.compile(r"(?:^|/)(?:api|v\d+|graphql|rest|internal|admin|auth|oauth|gateway)(?:/|$)", re.I)
_PARAM_IN_QS = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,40})=")
_PARAM_ASSIGN = re.compile(r"""[?&]?([A-Za-z_][A-Za-z0-9_]{1,40})=\$?\{?""")

# high-confidence secret patterns (tight, to avoid flagging ordinary code)
_SECRETS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github_fine", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b")),
    ("stripe_live", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("generic_key_assign", re.compile(
        r"""(?i)\b(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"""
        r"""["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{12,})["'`]""")),
]
_SECRET_ALLOW = re.compile(r"EXAMPLE|xxxx|XXXX|placeholder|your[_-]?key|<[^>]+>|\.\.\.|0{8,}", re.I)


def _strings(text):
    return [m.group(1) for m in _STR.finditer(text or "")]


def extract(text):
    """Return {endpoints,params,secrets,routes} as sets of findings for one JS blob."""
    endpoints, params, routes = set(), set(), set()
    for s in _strings(text):
        s = s.strip()
        if not s:
            continue
        head = s.split("?")[0].split("#")[0]            # test the PATH, keep query for param extraction
        if _REL_PATH.match(head):
            (endpoints if _API_HINT.search(head) else routes).add(head)
        for u in _ABS_URL.findall(s):
            endpoints.add(u.split("?")[0].split("#")[0])
        for p in _PARAM_IN_QS.findall(s):
            params.add(p)
    # params can also appear outside quoted strings (e.g. url concatenation) — scan raw text too
    for p in _PARAM_IN_QS.findall(text or ""):
        params.add(p)

    secrets = set()
    for label, pat in _SECRETS:
        for m in pat.finditer(text or ""):
            hit = m.group(1) if m.groups() else m.group(0)
            window = (text or "")[max(0, m.start() - 10): m.end() + 10]
            if _SECRET_ALLOW.search(window) or _SECRET_ALLOW.search(hit):
                continue
            secrets.add(f"{label}:{hit[:32]}")
    return {"endpoints": endpoints, "params": params, "secrets": secrets, "routes": routes}


def diff(old_text, new_text):
    """New-only findings: present in new bundle, absent from old. Secrets are reported if present
    in the NEW bundle at all (a newly exposed key is worth flagging even if it lingered)."""
    o, n = extract(old_text), extract(new_text)
    out = {}
    for k in ("endpoints", "params", "routes"):
        out["new_" + k] = sorted(n[k] - o[k])
    out["new_secrets"] = sorted(n["secrets"])           # any secret in the new bundle
    out["counts"] = {k: len(v) for k, v in out.items() if isinstance(v, list)}
    out["has_new"] = any(out[k] for k in out if k.startswith("new_") and isinstance(out[k], list))
    return out


def _curl(url, timeout=20):
    try:
        return subprocess.run(["curl", "-sL", "-m", str(timeout), url],
                              capture_output=True, text=True, timeout=timeout + 5, errors="ignore").stdout
    except Exception:
        return ""


def _read(path):
    return open(path, encoding="utf-8", errors="ignore").read()


def summarize(d):
    lines = []
    for key, label in [("new_endpoints", "NEW endpoint"), ("new_params", "NEW param"),
                       ("new_secrets", "NEW secret (!!)"), ("new_routes", "NEW route")]:
        items = d.get(key, [])
        if not items:
            continue
        lines.append(f"{len(items)} {label}(s):")
        for it in items[:20]:
            lines.append("   + " + it)
        if len(items) > 20:
            lines.append(f"   … +{len(items) - 20} more")
    if not lines:
        return ["no new endpoints/params/secrets/routes in the new bundle"]
    lines.append("")
    lines.append("-> hunt new_endpoints + new_params FIRST (fresh = low-dup); verify each secret, "
                 "then run /dedup check before drafting.")
    return lines


def _out(d, as_json):
    print(json.dumps(d, indent=2) if as_json else "\n".join(summarize(d)))


def main(argv=None):
    ap = argparse.ArgumentParser(description="diff JS bundles into a hunt list")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pd = sub.add_parser("diff"); pd.add_argument("--old", required=True); pd.add_argument("--new", required=True); pd.add_argument("--json", action="store_true")
    pf = sub.add_parser("fetch"); pf.add_argument("--old", required=True); pf.add_argument("--new", required=True); pf.add_argument("--json", action="store_true")
    ps = sub.add_parser("scan"); ps.add_argument("--new", required=True); ps.add_argument("--json", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)

    if a.cmd == "diff":
        _out(diff(_read(a.old), _read(a.new)), a.json)
    elif a.cmd == "fetch":
        _out(diff(_curl(a.old), _curl(a.new)), a.json)
    elif a.cmd == "scan":
        e = extract(_read(a.new))
        _out({"new_" + k: sorted(v) for k, v in e.items()} | {"has_new": True}, a.json)
    elif a.cmd == "selftest":
        return _selftest()
    return 0


def _selftest():
    old = """
      const API='/api/v1/users'; fetch('/api/v1/users?page=1');
      const home='/dashboard'; var k="AKIAIOSFODNN7EXAMPLE";
    """
    new = """
      const API='/api/v1/users'; fetch('/api/v1/users?page=1&sort=name');
      const admin='/api/v2/admin/impersonate?user_id=1';
      const home='/dashboard'; const billing='/settings/billing';
      const key="AKIA1234567890ABCDEF";
      const gkey="AIzaSyA1234567890abcdefghijklmnopqrstuv";
    """
    d = diff(old, new)
    assert "/api/v2/admin/impersonate" in d["new_endpoints"], d
    assert "/api/v1/users" not in d["new_endpoints"], d            # unchanged -> not new
    assert "user_id" in d["new_params"] and "sort" in d["new_params"], d
    assert "page" not in d["new_params"], d                        # present in old too
    assert "/settings/billing" in d["new_routes"], d
    assert "/dashboard" not in d["new_routes"], d
    assert any(s.startswith("aws_access_key:AKIA1234") for s in d["new_secrets"]), d
    assert any(s.startswith("google_api_key:") for s in d["new_secrets"]), d
    assert all("EXAMPLE" not in s for s in d["new_secrets"]), d    # allowlisted example not flagged
    assert d["has_new"] is True
    print("jsdiff.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
