#!/usr/bin/env python3
"""
verify.py — triage/verification gate for a draft finding BEFORE it is reported.

Answers the operator's question: "is this ready, with a real PoC + repro steps + demonstrated security
impact — accept it or not?" It is grounded in:
  - the triager-grade rules: per-class PoC minimums + the always-rejected list + severity honesty,
  - the PROGRAM's own scope and qualifying / non-qualifying lists (captured by scopeparse),
  - the dedup oracle.

Returns a verdict — READY / NEEDS_FIXES / DO_NOT_SUBMIT — with a per-check list, what's missing, a
readiness score, and (optional) a deep LLM triager opinion. Read-only: it never submits.

CLI:
  python3 verify.py check --file finding.json [--program paddle] [--deep]
  echo '{...}' | python3 verify.py check --stdin --program paddle
"""
import argparse
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# per-class minimum proof + the trap that auto-downgrades (from ywh-triager-grade-reports)
PER_CLASS = {
    "xss": ("executed payload in the victim's context (show it firing — not reflection or HTML-encoded)",
            [r"&lt;|&gt;|encoded|reflected only|appears in (the )?response"], r"alert\(|onerror|<script|executed|popup|document\.cookie"),
    "idor": ("a cross-account read/write of ANOTHER user's data (two identities)",
             [r"my own|same account|self"], r"account ?b|victim|other user|user ?2|different (account|user)|cross-account"),
    "bola": ("another object owner's data returned to a second identity",
             [], r"account ?b|other (user|tenant)|cross-account"),
    "ssrf": ("the response body (or OOB callback) proving the internal request — not a DNS/HTTP pingback only",
             [r"\bdns\b.*only|pingback only|just resolves|blind"], r"169\.254\.169\.254|metadata|internal|response body|collaborator"),
    "cors": ("reflected Origin + Access-Control-Allow-Credentials: true + a credentialed cross-origin read, shown in a browser",
             [r"access-control-allow-origin: ?\*|acao: ?\*"], r"allow-credentials: ?true|credentials.*true|read the response"),
    "sqli": ("extracted data or a clear DBMS behaviour difference (not an error message alone)",
             [r"error message|sql error|syntax error only"], r"extracted|union|sleep\(|version\(\)|dbms|time-based|boolean"),
    "rce": ("command output (e.g. id / whoami / uname)",
            [], r"uid=|gid=|whoami|root@|command output|/etc/passwd"),
    "open-redirect": ("a working redirect; any chained impact (e.g. token theft) reproduced end-to-end",
                      [r"self|same origin only"], r"location:|redirect(ed)? to|https?://(evil|attacker)"),
    "secret": ("the secret is VALID and you show what it unlocks (public pk_/maps/firebase keys are NOT findings)",
               [r"pk_live|publishable|google maps|firebase (api )?key|analytics"], r"valid|unlocks|authenticated|access granted"),
    "ssti": ("server-side evaluation proven ({{7*7}} rendering in Angular is client-side, not SSTI)",
             [r"angular|client-side|\{\{7\*7\}\} in the (dom|browser)"], r"49|server-side|rce|config|class"),
    "lfi": ("actual file contents returned (a 200 on a traversal path is not enough)",
            [r"200 only|no file content"], r"root:.*:0:0|/etc/passwd|file contents|base64"),
    "csrf": ("a state-changing action performed cross-site with real impact (not logout/login/cart)",
             [r"logout|login|unauthenticated|cart"], r"email change|password|state change|account"),
}

# never-submit, independent of class (always-rejected list)
ALWAYS_REJECT = [
    (r"self[- ]?xss", "self-XSS (cannot impact other users)"),
    (r"clickjack|ui redress", "clickjacking / UI-redressing"),
    (r"missing (security )?header|hsts|x-frame-options", "missing security headers without a demonstrated exploit"),
    (r"rate.?limit|brute.?force|captcha", "rate-limiting / brute-force / captcha"),
    (r"user enumeration|email enumeration", "user enumeration"),
    (r"spf|dkim|dmarc", "email records (SPF/DKIM/DMARC) alone"),
    (r"\{\{7\*7\}\}.*angular|angular.*\{\{7\*7\}\}", "{{7*7}} in Angular is client-side (CSTI), not server-side SSTI"),
    (r"pk_live|publishable key|google maps api|firebase config", "public/publishable API key (not a finding)"),
    (r"graphql introspection", "GraphQL introspection enabled (non-qualifying)"),
    (r"pre-?account takeover|account creation via oauth", "pre-account-takeover via OAuth (non-qualifying)"),
    (r"tabnabbing|broken link|social media hijack", "tabnabbing / broken-link hijack"),
]

REQUIRED = ["vuln_class", "url", "title"]
PROOF_FIELDS = ["poc", "request", "response", "evidence", "steps"]


def _text(f):
    return " ".join(str(f.get(k, "")) for k in
                    ("title", "steps", "poc", "impact", "request", "response", "evidence", "proof_note")).lower()


def _load_scope(program, base):
    if not program:
        return None
    try:
        import targets as T
        return T.load(program, base=base)
    except Exception:  # noqa: BLE001
        return None


def _in_scope(url, scope):
    if not scope:
        return None
    try:
        import scope as SCMOD
        s = SCMOD.Scope(scope.get("in_scope", []), scope.get("out_of_scope", []))
        return s.in_scope_host(url)
    except Exception:  # noqa: BLE001
        return None


def verify_finding(f, program=None, base=DEFAULT_BASE):
    checks, missing = [], []
    cls = (f.get("vuln_class") or "").lower().strip()
    sev = (f.get("severity") or "").lower().strip()
    url = f.get("url", "")
    blob = _text(f)
    scope = _load_scope(program or f.get("program"), base)

    def add(name, ok, note=""):
        checks.append({"check": name, "pass": bool(ok), "note": note})

    # 1) completeness
    for r in REQUIRED:
        if not f.get(r):
            missing.append(r)
    has_steps = bool(f.get("steps"))
    has_proof = any(f.get(k) for k in PROOF_FIELDS if k != "steps") or bool(f.get("_images"))
    add("has repro steps", has_steps, "" if has_steps else "add numbered reproduction steps")
    add("has PoC / evidence", has_proof, "" if has_proof else "attach the request/response/PoC that proves it")
    add("has impact stated", bool(f.get("impact")), "" if f.get("impact") else "state the concrete security impact")
    add("required fields present", not missing, ("missing: " + ", ".join(missing)) if missing else "")

    # 2) scope
    insc = _in_scope(url, scope)
    if insc is None:
        add("in scope", True, "scope unknown (no program) — verify manually")
    else:
        add("in scope", insc, "" if insc else f"{url} is NOT in the program scope → out-of-scope")

    # 3) qualifying / non-qualifying (from the program page)
    hard_reject = None
    if scope:
        nonq = " ".join(scope.get("non_qualifying", [])).lower()
        qualc = scope.get("qualifying_classes") or []
        if qualc and cls and cls not in qualc:
            add("class is qualifying", False, f"'{cls}' is not in this program's qualifying list {qualc}")
        else:
            add("class is qualifying", True, "")
        # finding text matching a non-qualifying bullet
        for bullet in scope.get("non_qualifying", []):
            key = bullet.lower().split("(")[0].strip()
            if key and len(key) > 6 and key in blob:
                hard_reject = f"matches program NON-qualifying: {bullet[:60]}"
                break

    # 4) always-rejected patterns
    for pat, why in ALWAYS_REJECT:
        if re.search(pat, blob):
            # allow if it's clearly chained to real impact
            if not re.search(r"chain|leads to|results in|account takeover|ato|rce|exfiltrat", blob):
                hard_reject = hard_reject or f"always-rejected: {why}"
            break
    add("not an always-rejected class", hard_reject is None, hard_reject or "")

    # 4b) RTFS / Informative — structural, vendor-agnostic. A hold is not drafted.
    try:
        import disposition as DP
        dres = DP.check(f, program=program or f.get("program"), base=base)
    except Exception as e:  # noqa: BLE001
        dres = {"verdict": "HOLD_RTFS", "reason": f"disposition gate error: {e}"}
    held = dres.get("verdict") != "PASS"
    add("disposition (not RTFS / Informative)", not held,
        "" if not held else f"{dres.get('verdict')}: {dres.get('reason','')}")
    if held:
        hard_reject = hard_reject or f"{dres.get('verdict')}: {dres.get('reason','')}"

    # 5) per-class PoC minimum
    if cls in PER_CLASS:
        need, downgrade_pats, proof_pat = PER_CLASS[cls]
        proven = bool(re.search(proof_pat, blob)) if proof_pat else has_proof
        downgraded = any(re.search(p, blob) for p in downgrade_pats)
        add(f"PoC minimum for {cls}", proven and not downgraded,
            "" if (proven and not downgraded) else f"needs: {need}")
        if not proven:
            missing.append(f"{cls}-poc-minimum")
    else:
        add("PoC minimum", has_proof, "unknown class — ensure the PoC proves real impact")

    # 6) severity honesty
    if sev in ("critical", "high"):
        strong = re.search(r"account takeover|ato|rce|mass|admin|other user|cross-account|command output|"
                           r"metadata|credentials|extracted|full access", blob)
        add("severity supported by evidence", bool(strong),
            "" if strong else f"'{sev}' needs stronger demonstrated impact, or lower the severity")

    # 7) dedup
    try:
        import dedup as D
        res = D.Corpus(program or f.get("program") or "", base=base).check(
            {"vuln_class": cls, "url": url, "title": f.get("title", "")})
        dv = (res or {}).get("verdict", "NOVEL")
        add("dedup (not a known duplicate)", dv != "LIKELY_DUP", f"dedup verdict: {dv}")
        dedup = res
    except Exception:  # noqa: BLE001
        dedup = {"verdict": "unknown"}
        add("dedup (not a known duplicate)", True, "dedup oracle unavailable — check manually")

    # 8) RTFS / Informative disposition gate (generic — catches "hypothetical precondition" closures)
    try:
        import disposition as DSP
        dsp = DSP.check(f, program=program, base=base)
        dv = dsp.get("verdict", "PASS")
        add("disposition (not RTFS/Informative)", dv == "PASS",
            "" if dv == "PASS" else f"{dv}: {dsp.get('reason', '')[:150]}")
        if dv != "PASS":
            hard_reject = hard_reject or f"disposition gate: {dv}"
    except Exception:  # noqa: BLE001
        add("disposition (not RTFS/Informative)", True, "disposition gate unavailable")

    # 9) generic precondition check — the #1 RTFS cause: impact needs a victim secret the PoC never obtains
    _precond = re.compile(r"stolen session|obtain(?:s|ed|ing)? (?:a |the )?(?:victim'?s? )?(?:vendor |user )?session|"
                          r"cookie theft|session hijack|shared machine|physical access|\bmitm\b|man-in-the-middle|"
                          r"anyone who obtains|attacker who obtains|leaked (?:transaction|object|order|invoice) id")
    _proven = re.compile(r"document\.cookie|samesite\s*=\s*none|xss.{0,80}(executed|fired|exfiltrat)|"
                         r"cross-site form|csrf reproduced|in-scope (?:api|response|endpoint).{0,60}(?:uuid|id)|"
                         r"response (?:lists|returned) (?:another|other|victim)|enumerable|sequential id|"
                         r"demonstrated (?:a |the )?(?:way|method) to obtain|obtained from an in-scope")
    if _precond.search(blob) and not _proven.search(blob):
        add("impact precondition is demonstrated (not hypothetical)", False,
            "impact assumes obtaining a victim session/secret the PoC never obtains — show how an attacker "
            "gets it (XSS/CSRF/enumerable id/in-scope oracle), or it's RTFS 'hypothetical'")
        hard_reject = hard_reject or "hypothetical precondition (victim secret not obtained)"

    fails = [c for c in checks if not c["pass"]]
    score = round(100 * (len(checks) - len(fails)) / max(1, len(checks)))
    if hard_reject or insc is False:
        verdict = "DO_NOT_SUBMIT"
    elif fails:
        verdict = "NEEDS_FIXES"
    else:
        verdict = "READY"
    return {"verdict": verdict, "score": score, "program": program or f.get("program"),
            "vuln_class": cls, "severity": sev, "url": url,
            "checks": checks, "failed": [c["check"] for c in fails], "missing": missing,
            "dedup": dedup, "accept": verdict == "READY"}


def deep_opinion(f, det, program=None, base=DEFAULT_BASE, timeout=180):
    """Optional strict LLM triager opinion (cursor-agent). Returns dict or None."""
    try:
        import agent as A
        scope = _load_scope(program or f.get("program"), base) or {}
        task = ("You are a STRICT bug-bounty triager. Decide if this draft finding is submittable. "
                "Be harsh: reflection-only, error-only, no-impact, theoretical, or non-qualifying = REJECT.\n\n"
                f"FINDING:\n{json.dumps(f, indent=2)[:3500]}\n\n"
                f"PROGRAM non-qualifying: {scope.get('non_qualifying', [])[:20]}\n"
                f"Deterministic pre-check: verdict={det['verdict']}, failed={det['failed']}\n\n"
                "Reply ONLY JSON: {\"verdict\":\"READY|NEEDS_FIXES|DO_NOT_SUBMIT\",\"reasons\":[...],"
                "\"missing\":[...],\"severity_opinion\":\"...\"}")
        r = A.run_agent(task, context=None, timeout=timeout, attempts=1)
        js = A.extract_json(r.get("result", "")) if hasattr(A, "extract_json") else None
        if isinstance(js, dict) and js.get("verdict"):
            js["model"] = r.get("model")
            return js
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:120]}
    return None


# ------- secure file intake (uploaded report + evidence) -------
ALLOWED_TEXT = {".md", ".txt", ".json", ".log", ".har", ".csv", ".xml", ".yaml", ".yml", ".http", ".nb"}
ALLOWED_BIN = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"}
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
_VERDICT_ORDER = {"READY": 0, "NEEDS_FIXES": 1, "DO_NOT_SUBMIT": 2}


def _safe_name(name):
    """basename only + whitelist chars — defeats path traversal (../), null bytes, odd names."""
    b = os.path.basename(str(name or "").replace("\x00", "")).strip()
    b = re.sub(r"[^A-Za-z0-9._-]", "_", b)[:120].lstrip(".") or "file"
    return b


def ingest_files(files, program=None, base=DEFAULT_BASE):
    """Save uploaded files [{name,b64,type?}] SECURELY under the engagement dir; return merged text of
    text files + counts. Hardened: basename-only names, allow-list extensions, per-file + total size
    caps, path-escape guard, chmod 600, never executed/served. Returns {saved,rejected,text,images,dir}."""
    import base64
    import time as _t
    slug = re.sub(r"[^a-z0-9._-]+", "-", (program or "adhoc").lower()).strip("-") or "adhoc"
    root = os.path.realpath(os.path.join(os.path.expanduser(base), slug, "verify-uploads",
                                         _t.strftime("%Y%m%d-%H%M%S")))
    saved, rejected, texts, images, total = [], [], [], 0, 0
    for f in (files or [])[:40]:
        name = _safe_name(f.get("name"))
        ext = os.path.splitext(name)[1].lower()
        try:
            raw = base64.b64decode((f.get("b64") or "").encode(), validate=False)
        except Exception:  # noqa: BLE001
            rejected.append({"name": name, "reason": "invalid base64"}); continue
        if len(raw) > MAX_FILE:
            rejected.append({"name": name, "reason": f"too large ({len(raw)//1024}KB > {MAX_FILE//1048576}MB)"}); continue
        if total + len(raw) > MAX_TOTAL:
            rejected.append({"name": name, "reason": "total upload cap exceeded"}); break
        if ext not in ALLOWED_TEXT and ext not in ALLOWED_BIN:
            rejected.append({"name": name, "reason": f"type '{ext or '?'}' not allowed"}); continue
        path = os.path.realpath(os.path.join(root, name))
        if not path.startswith(root + os.sep):          # defense-in-depth: never write outside the dir
            rejected.append({"name": name, "reason": "path escape blocked"}); continue
        os.makedirs(root, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(raw)
        os.chmod(path, 0o600)
        total += len(raw)
        saved.append({"name": name, "bytes": len(raw)})
        if ext in ALLOWED_TEXT:
            texts.append(f"--- {name} ---\n" + raw.decode("utf-8", "ignore")[:20000])
        else:
            images += 1
    return {"saved": saved, "rejected": rejected, "text": "\n".join(texts),
            "images": images, "dir": root if saved else None}


def combine_verdict(det, opinion):
    """Final trigger = the STRICTER of the deterministic gate and the expert (LLM) review."""
    v = det.get("verdict", "NEEDS_FIXES")
    ov = (opinion or {}).get("verdict")
    if ov in _VERDICT_ORDER and _VERDICT_ORDER[ov] > _VERDICT_ORDER.get(v, 1):
        v = ov
    return v


# ------- extract a finding straight from an uploaded report (md / txt / json) -------
CLASS_HINTS = [
    (r"\bsql ?injection|\bsqli\b", "sqli"), (r"\bnosql", "nosqli"),
    (r"cross.?site script|\bxss\b", "xss"), (r"remote code|\brce\b", "rce"),
    (r"\bidor\b|insecure direct object|broken object level|\bbola\b|broken access", "idor"),
    (r"privilege escalation", "idor"), (r"authentication bypass|auth bypass|broken auth", "auth-bypass"),
    (r"business logic", "business-logic"), (r"\bssrf\b|server.?side request|xspa", "ssrf"),
    (r"\blfi\b|local file|path traversal", "lfi"), (r"\bxxe\b", "xxe"), (r"\bcors\b", "cors"),
    (r"\bcsrf\b|cross.?site request", "csrf"), (r"open redirect", "open-redirect"),
    (r"exposed secret|leaked (key|credential|token)|hardcoded secret", "secret"),
    (r"\bssti\b|template injection", "ssti"), (r"\bjwt\b", "auth-bypass"),
    (r"graphql", "graphql"), (r"webhook", "webhook"), (r"\bmcp\b", "mcp"),
]


def _first(text, pats, group=1):
    for p in pats:
        m = re.search(p, text, re.I | re.M)
        if m:
            return (m.group(group) or "").strip()
    return ""


def _section_md(text, keys):
    """Grab the body under a heading like 'Steps to reproduce' until the next heading."""
    kset = [k.lower() for k in keys]
    out, cap = [], False
    for ln in (text or "").splitlines():
        head = bool(re.match(r"^\s*#{1,6}\s", ln)) or (0 < len(ln.strip()) < 42 and ln.strip().endswith(":"))
        label = ln.strip().lstrip("#").strip().rstrip(":").strip().lower()
        if cap and head and label not in kset:
            break
        if not cap and head and any(label == k or label.startswith(k) for k in kset):
            cap = True
            continue
        if cap:
            out.append(ln)
    return "\n".join(out).strip()[:4000]


def extract_finding(text):
    """Best-effort parse of a report into {vuln_class,severity,url,title,steps,poc,impact}. Only non-empty."""
    t = text or ""
    low = t.lower()
    f = {}
    f["title"] = _first(t, [r"^\s*#\s*(.+)$", r"^\s*title\s*[:\-]\s*(.+)$", r'"title"\s*:\s*"([^"]+)"'])[:160]
    f["url"] = _first(t, [r"^\s*(?:url|affected|endpoint|target)\s*[:\-]\s*(\S+)",
                          r'"url"\s*:\s*"([^"]+)"', r"(https?://[^\s\"')<>]+)"])
    sev = _first(t, [r"^\s*severity\s*[:\-]\s*(critical|high|medium|low)",
                     r'"severity"\s*:\s*"(critical|high|medium|low)', r"\b(critical|high|medium|low)\b"])
    if sev:
        f["severity"] = sev.lower()
    cls = _first(t, [r"^\s*(?:class|vuln(?:erability)? ?type|type)\s*[:\-]\s*([A-Za-z\- ]{2,30})",
                     r'"vuln_class"\s*:\s*"([^"]+)"'])
    if cls:
        f["vuln_class"] = cls.strip().lower().replace(" ", "-")
    else:
        for p, c in CLASS_HINTS:
            if re.search(p, low):
                f["vuln_class"] = c
                break
    f["steps"] = _section_md(t, ["steps to reproduce", "reproduction", "steps", "repro"])
    f["poc"] = _section_md(t, ["proof of concept", "poc", "exploit", "payload"]) \
        or "\n".join(re.findall(r"```.*?```", t, re.S))[:2000]
    f["impact"] = _section_md(t, ["security impact", "impact"])
    return {k: v for k, v in f.items() if v}


def _main(argv=None):
    ap = argparse.ArgumentParser(description="finding verification / triage gate")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check")
    pc.add_argument("--file"); pc.add_argument("--stdin", action="store_true")
    pc.add_argument("--program"); pc.add_argument("--deep", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    f = json.loads(sys.stdin.read()) if a.stdin else json.load(open(os.path.expanduser(a.file)))
    out = verify_finding(f, program=a.program, base=a.base)
    if a.deep:
        out["triager_opinion"] = deep_opinion(f, out, program=a.program, base=a.base)
    print(json.dumps(out, indent=2))
    return 0 if out["verdict"] != "DO_NOT_SUBMIT" else 2


def _selftest():
    # 1) strong IDOR with cross-account proof -> READY
    good = {"program": "", "vuln_class": "idor", "severity": "high",
            "title": "IDOR on /api/orders/{id} exposes another user's order",
            "url": "https://app.example.com/api/orders/1032",
            "steps": "1) login as account A 2) note order id 3) as account B, GET /api/orders/1032",
            "poc": "curl as account B returns account A's order (victim/other user) data",
            "response": "{\"owner\":\"userA\",\"total\":99.0} returned to account B (cross-account)",
            "impact": "any user can read any other user's orders (PII)"}
    r = verify_finding(good)
    assert r["verdict"] in ("READY", "NEEDS_FIXES"), r
    assert any(c["check"].startswith("PoC minimum for idor") and c["pass"] for c in r["checks"]), r

    # 2) self-XSS -> DO_NOT_SUBMIT
    bad = {"vuln_class": "xss", "severity": "medium", "title": "Self-XSS in settings",
           "url": "https://app.example.com/settings", "steps": "paste payload into own field",
           "poc": "self-xss fires alert(1) in my own session", "impact": "none really"}
    rb = verify_finding(bad)
    assert rb["verdict"] == "DO_NOT_SUBMIT", rb

    # 3) missing PoC -> NEEDS_FIXES
    weak = {"vuln_class": "ssrf", "severity": "high", "title": "maybe SSRF",
            "url": "https://app.example.com/fetch", "impact": "could be bad"}
    rw = verify_finding(weak)
    assert rw["verdict"] in ("NEEDS_FIXES", "DO_NOT_SUBMIT") and not rw["accept"], rw

    # 4) SECURE FILE INTAKE — path traversal, bad type, oversized, text extraction, image count
    import base64 as _b64
    import tempfile as _tf
    bse = _tf.mkdtemp()
    files = [
        {"name": "report.md", "b64": _b64.b64encode(b"# IDOR\naccount B reads account A order (cross-account)").decode()},
        {"name": "../../../tmp/evil.md", "b64": _b64.b64encode(b"path traversal attempt").decode()},  # traversal + allowed ext
        {"name": "shell.php", "b64": _b64.b64encode(b"<?php system($_GET[c]);?>").decode()},  # bad type -> reject
        {"name": "x.exe", "b64": _b64.b64encode(b"MZ").decode()},                             # bad type -> reject
        {"name": "big.txt", "b64": _b64.b64encode(b"A" * (MAX_FILE + 1)).decode()},           # oversized -> reject
        {"name": "shot.png", "b64": _b64.b64encode(b"\x89PNG\r\n\x1a\n").decode()},           # image
    ]
    ing = ingest_files(files, program="acme-up", base=bse)
    saved = [s["name"] for s in ing["saved"]]
    rej = " ".join(r["name"] + ":" + r["reason"] for r in ing["rejected"])
    assert "report.md" in saved and "shot.png" in saved, saved
    assert "evil.md" in saved, saved                    # traversal collapsed to basename, stored IN the dir
    assert "shell.php" in rej and "x.exe" in rej and "big.txt" in rej, rej
    assert "cross-account" in ing["text"] and ing["images"] == 1, ing
    # traversal defeated: nothing written outside the upload dir
    import glob as _g
    for p in _g.glob(bse + "/**", recursive=True):
        assert os.path.isdir(p) or "verify-uploads" in p, p
    # 5) combined verdict = stricter of gate + expert opinion
    assert combine_verdict({"verdict": "READY"}, {"verdict": "DO_NOT_SUBMIT"}) == "DO_NOT_SUBMIT"
    assert combine_verdict({"verdict": "NEEDS_FIXES"}, {"verdict": "READY"}) == "NEEDS_FIXES"
    # 6) extract a finding straight from an uploaded report
    report = ("# IDOR on /api/orders exposes other users' orders\n"
              "Severity: High\nURL: https://app.example.com/api/orders/1032\n\n"
              "## Steps to reproduce\n1) login as A\n2) as account B, GET /api/orders/1032\n\n"
              "## Proof of concept\n```\ncurl -H 'cookie: B' .../orders/1032  -> account A's order\n```\n\n"
              "## Impact\nany user reads any other user's orders (cross-account PII)")
    ex = extract_finding(report)
    assert ex.get("vuln_class") == "idor", ex
    assert ex.get("severity") == "high" and "orders/1032" in ex.get("url", ""), ex
    assert "login as A" in ex.get("steps", "") and "curl" in ex.get("poc", "") and "cross-account" in ex.get("impact", ""), ex
    print("verify.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
