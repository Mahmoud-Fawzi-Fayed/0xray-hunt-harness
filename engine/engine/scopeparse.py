#!/usr/bin/env python3
"""
scopeparse.py — turn a pasted bug-bounty PROGRAM PAGE (YesWeHack / HackerOne / Bugcrowd-style text)
into a full engine scope file: in/out-scope hosts, the mandatory User-Agent suffix, qualifying +
non-qualifying vuln classes, the reward grid, and the rules-of-engagement. Adding a target becomes
"paste the page" — no hand-editing. Also writes a human-readable program.md.

CLI:
  python3 scopeparse.py parse --file program.txt [--name paddle] [--register]
  echo "<pasted page>" | python3 scopeparse.py parse --stdin --name paddle --register
  python3 scopeparse.py selftest
"""
import argparse
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import scopefetch as SF  # noqa: E402

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# free-text vuln name -> engine vuln class (drives skill_map dispatch + ranking bias)
VULN_MAP = [
    (r"\bsql", "sqli"), (r"nosql", "nosqli"), (r"cross.?site script|\bxss\b", "xss"),
    (r"remote code|\brce\b", "rce"), (r"idor|insecure direct object|\bbola\b", "idor"),
    (r"privilege escalation", "auth-bypass"), (r"authentication bypass|broken auth", "auth-bypass"),
    (r"business logic", "business-logic"), (r"\bssrf\b|xspa", "ssrf"), (r"\blfi\b|local file", "lfi"),
    (r"\brfi\b", "lfi"), (r"\bxxe\b", "xxe"), (r"\bcors\b", "cors"),
    (r"csrf|cross.?site request", "csrf"), (r"open redirect", "open-redirect"),
    (r"exposed secret|credential|sensitive information", "secret"), (r"graphql", "graphql"),
    (r"deserial", "deserialization"), (r"template injection|\bssti\b", "ssti"),
    (r"file upload", "file-upload"), (r"race condition", "race-condition"),
    (r"subdomain takeover", "subdomain"), (r"\boauth\b", "oauth"), (r"\bsaml\b", "saml"),
    (r"\bmfa\b|\b2fa\b", "mfa"), (r"cache", "cache-poison"), (r"host header", "host-header"),
    (r"http.?smuggl", "http-smuggling"), (r"websocket", "websocket"),
]


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "program"


def _section(text, start_pats, end_pats):
    lo = None
    for p in start_pats:
        m = re.search(p, text, re.I)
        if m:
            lo = m.end()
            break
    if lo is None:
        return ""
    hi = len(text)
    for p in end_pats:
        m = re.search(p, text[lo:], re.I)
        if m:
            hi = lo + m.start()
            break
    return text[lo:hi]


def _hosts(block):
    out = []
    for m in re.findall(r"https?://[A-Za-z0-9.\-]+", block or ""):
        h = SF._host(m)
        if h and h not in out:
            out.append(h)
    return out


def _lines(block, maxn=40):
    return [ln.strip() for ln in (block or "").splitlines() if len(ln.strip()) > 3][:maxn]


def _classes(block):
    out = []
    for ln in (block or "").splitlines():
        s = ln.strip().lower()
        for pat, cls in VULN_MAP:
            if re.search(pat, s) and cls not in out:
                out.append(cls)
    return out


def parse(text, name=None):
    m = re.search(r"^(.+?)\s+(Public|Private)\s+Bug Bounty", text, re.I | re.M) \
        or re.search(r"^(.+?Bug Bounty Program)", text, re.M)
    prog_name = (m.group(1).strip() if m else "program")
    slug = _slug(name or re.sub(r"\.com.*$", "", prog_name.split()[0]))
    public = bool(re.search(r"\bPublic\b", text))
    in_scope = _hosts(_section(text, [r"Scope\s+Type", r"\bScopes\b"], [r"Out of scope"]))
    out_scope = _hosts(_section(text, [r"Out of scope"], [r"Vulnerability types", r"Program Rules"]))
    ua_sfx = ""
    mu = re.search(r"user-agent[^']*'\s*([^']+?)\s*'", text, re.I)
    if mu:
        ua_sfx = mu.group(1).strip()
    browser = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
    user_agent = (browser + " " + ua_sfx).strip() if ua_sfx else browser
    qual = _section(text, [r"Qualifying vulnerabilities"], [r"Non-qualifying"])
    nonq = _section(text, [r"Non-qualifying vulnerabilities"], [r"Hunting requirements", r"Credits", r"\Z"])
    rew = _section(text, [r"\bReward\b"], [r"\bScopes\b"])
    return {
        "slug": slug, "name": prog_name, "public": public,
        "in_scope": in_scope, "out_of_scope": out_scope,
        "user_agent_suffix": ua_sfx, "user_agent": user_agent,
        "qualifying": _lines(qual), "non_qualifying": _lines(nonq), "qualifying_classes": _classes(qual),
        "rewards": [ln.strip() for ln in rew.splitlines() if "$" in ln][:10],
        "no_scanner": bool(re.search(r"automated scanners|large amount", text, re.I)),
        "no_disclose": bool(re.search(r"No vulnerability disclosure", text, re.I)),
        "sandbox": bool(re.search(r"\bsandbox\b", text, re.I)),
    }


def to_scope(p):
    seeds = ["https://" + h for h in p["in_scope"] if "*" not in h][:50]
    roe = [f"- SCOPE: only the listed in-scope hosts; everything else is out of scope"
           + (f" (explicitly incl. {', '.join(p['out_of_scope'])})" if p["out_of_scope"] else "") + "."]
    if p["sandbox"]:
        roe.append("- Financial/checkout tests ONLY on sandbox-* hosts; never run test transactions on production.")
    if p["no_scanner"]:
        roe.append("- NO automated scanners / NO high-traffic / NO brute-force (rate-limit, user-enum, "
                   "weak-password, blind SSRF w/o PoC are non-qualifying).")
    if p["qualifying"]:
        roe.append("- QUALIFYING: " + "; ".join(p["qualifying"][:16]))
    if p["non_qualifying"]:
        roe.append("- NON-QUALIFYING (do not chase): " + "; ".join(p["non_qualifying"][:24]))
    if p["no_disclose"]:
        roe.append("- No public disclosure: keep findings INTERNAL (draft + operator email only).")
    roe.append("- Redact PII in evidence; verify-only on exposed creds; third-party testing tools "
               "(e.g. XSS Hunter) not allowed — self-hosted OOB only.")
    return {
        "name": p["slug"], "program_name": p["name"], "platform": "yeswehack", "public": p["public"],
        "in_scope": p["in_scope"], "out_of_scope": p["out_of_scope"], "seeds": seeds, "monitor_apexes": [],
        "self_register_ok": False, "skip_param_mining": bool(p["no_scanner"]),
        "user_agent": p["user_agent"], "impersonate": "chrome", "proxy": "",
        "qualifying_classes": p["qualifying_classes"], "qualifying": p["qualifying"],
        "non_qualifying": p["non_qualifying"], "rewards": p["rewards"],
        "roe_extra": "\n".join(roe) + "\n",
    }


def program_md(p):
    def bl(items, empty):
        return "\n".join(f"- {x}" for x in items) if items else empty
    return "\n".join([
        f"# {p['name']} ({'public' if p['public'] else 'private'})", "",
        "## In scope", bl(p["in_scope"], "- (none parsed)"), "",
        "## Out of scope", bl(p["out_of_scope"], "- all domains not listed"), "",
        f"## Mandatory User-Agent\n`{p['user_agent']}`", "",
        "## Rewards", bl(p["rewards"], "- (see program)"), "",
        "## Qualifying vulnerabilities", bl(p["qualifying"], "- (see program)"), "",
        "## Non-qualifying vulnerabilities", bl(p["non_qualifying"], "- (see program)"),
        f"\n## Mapped hunt classes\n{', '.join(p['qualifying_classes']) or '(auto)'}", ""])


def register(scope, p, base=DEFAULT_BASE):
    td = os.path.join(os.path.expanduser(base), "_targets")
    os.makedirs(td, exist_ok=True)
    path = os.path.join(td, scope["name"] + ".json")
    json.dump(scope, open(path, "w"), indent=2)
    eng = os.path.join(os.path.expanduser(base), scope["name"])
    os.makedirs(eng, exist_ok=True)
    open(os.path.join(eng, "program.md"), "w").write(program_md(p))
    return path


def _main(argv=None):
    ap = argparse.ArgumentParser(description="program page -> engine scope")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("parse")
    pp.add_argument("--file"); pp.add_argument("--stdin", action="store_true")
    pp.add_argument("--name"); pp.add_argument("--register", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    text = sys.stdin.read() if a.stdin else open(os.path.expanduser(a.file)).read()
    p = parse(text, name=a.name)
    sc = to_scope(p)
    if a.register:
        path = register(sc, p, base=a.base)
        print(f"registered {sc['name']}: {len(sc['in_scope'])} in-scope, {len(sc['out_of_scope'])} oos, "
              f"UA+='{p['user_agent_suffix']}', classes={sc['qualifying_classes']} -> {path}")
    else:
        print(json.dumps(sc, indent=2))
    return 0


def _selftest():
    sample = ("Acme Public Bug Bounty Program\nPublic\n"
              "Scope  Type\nhttps://app.acme.com\nWeb application\nhttps://api.acme.com\nAPI\n"
              "Out of scopes\nhttps://blog.acme.com\n"
              "Vulnerability types\nQualifying vulnerabilities\nSQL Injection (SQLi)\n"
              "Cross-Site Scripting (XSS)\nIDOR\nRemote Code Execution (RCE)\n"
              "Non-qualifying vulnerabilities\nClickjacking/UI redressing\nSelf-XSS\n"
              "Hunting requirements\nUser agent\n"
              "Please append to your user-agent header the following value: ' ACME-BB '.")
    p = parse(sample)
    sc = to_scope(p)
    assert sc["in_scope"] == ["app.acme.com", "api.acme.com"], sc["in_scope"]
    assert sc["out_of_scope"] == ["blog.acme.com"], sc["out_of_scope"]
    assert sc["user_agent"].endswith("ACME-BB"), sc["user_agent"]
    assert {"sqli", "xss", "idor", "rce"} <= set(sc["qualifying_classes"]), sc["qualifying_classes"]
    assert sc["name"] == "acme" and sc["skip_param_mining"] is False, sc
    print("scopeparse.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
