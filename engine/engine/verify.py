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
    "xxe": ("external entity parsed and data exfiltrated or SSRF proven (not just a DTD error)",
            [r"error message only|dtd error|xml error"], r"file:///|SYSTEM|exfiltrat|/etc/passwd|oob|collaborator"),
    "nosqli": ("extracted data or behaviour difference proving injection (not just an error)",
               [r"error message only|stack trace only"], r"extracted|boolean|sleep|tojson|regex|noSQL|where|admin.*true"),
    "crlf": ("injected header appears in the HTTP response (not just reflected in body)",
             [r"reflected in body|html only"], r"set-cookie|location:|http/|\\r\\n|%0d%0a.*:"),
    "deserialization": ("code execution or object instantiation proven (not just a gadget chain theory)",
                        [r"theoretical|gadget.*only|might work"], r"executed|whoami|uid=|rce|object instantiat|class.*forName"),
    "cache-poison": ("poisoned response served to a DIFFERENT user/session (not just your own cached response)",
                     [r"own (session|cache)|same user|self-poison"], r"other user|victim|different session|cache key|x-cache.*hit"),
    "file-upload": ("uploaded file executed or served dangerously (not just upload accepted)",
                    [r"upload accepted|stored only|filename reflected"], r"executed|rce|xss|served as|content-type.*html|phpinfo"),
    "race-condition": ("state inconsistency demonstrated with real impact (not just parallel 200s)",
                       [r"parallel 200|concurrent requests only|no state change"], r"double|inconsisten|extra|duplicate|negative balance|coupon.*twice"),
    "http-smuggling": ("desync proven: second request interpreted differently by front/back (not just a CL/TE header)",
                       [r"header only|cl.te header|theory"], r"desync|smuggl|second request|poison|response queue"),
    "prototype-pollution": ("polluted property reaches a security-sensitive sink (not just __proto__ set)",
                            [r"__proto__.*set only|no sink|prototype.*modified"], r"rce|xss|bypass|admin|isAdmin|sink|constructor"),
    "jwt": ("forged/modified token accepted by the server with privilege escalation (not just decoded)",
            [r"decoded only|header (read|viewed)|payload (read|viewed)"], r"forged|accepted|alg.*none|key confusion|privilege|admin|role"),
    "saml": ("authentication bypass or assertion forged (not just metadata exposed)",
             [r"metadata only|certificate.*exposed"], r"bypass|forged|impersonat|assertion.*accepted|as another user"),
    "ldap": ("LDAP injection proven with data extraction or auth bypass (not just an error)",
             [r"error message only|ldap error"], r"extracted|bypass|bind.*success|wildcard|dn=|admin"),
    "host-header": ("injected Host header changes server behaviour with security impact (not just reflected)",
                    [r"reflected only|no impact"], r"password reset|redirect|cache.*poison|ssrf|link.*evil|host.*inject"),
    "dom-xss": ("DOM-based XSS executing in victim's browser context (not just source/sink identified)",
                [r"source.*identified|sink.*identified|potential"], r"executed|alert|document\.cookie|fired|dom.*xss.*proof"),
    "pdf-ssrf": ("SSRF via PDF generation proven with internal data or OOB callback (not just PDF generated)",
                 [r"pdf generated|no callback|no internal"], r"169\.254|metadata|internal|collaborator|oob|ssrf.*pdf"),
    "auth-bypass": ("authentication bypass proven: accessed protected resource without valid credentials",
                    [r"login page|redirect.*login|no access"], r"bypass|unauthenticat|without (auth|cred|login)|admin|protected.*access"),
    "oauth": ("OAuth misconfiguration with real impact: token theft, account takeover, or scope escalation",
              [r"best practice|recommendation|informational"], r"token.*steal|redirect_uri|takeover|scope.*escalat|state.*missing.*impact|code.*intercept"),
    "2fa-bypass": ("2FA/MFA bypass proven: accessed account without completing second factor",
                   [r"2fa enabled|mfa present|no bypass"], r"bypass|skip|without.*2fa|without.*mfa|direct access|rate.?limit.*otp"),
    "business-logic": ("business logic flaw with real financial or security impact (not just unexpected behavior)",
                       [r"no impact|cosmetic|ui bug|expected behavior"], r"negative|free|discount|bypass.*pay|privilege|unauth.*action|price.*manipul|coupon|credit"),
    "graphql": ("GraphQL vulnerability with data access or mutation beyond authorization (not just introspection)",
                [r"introspection only|schema.*exposed|no data"], r"unauthorized.*data|mutation|query.*other|batch|depth|alias.*bypass|dos|nested"),
    "webhook": ("webhook vulnerability with real impact: SSRF, data exfiltration, or auth bypass via callback manipulation",
                [r"webhook exists|endpoint.*found|no impact"], r"ssrf|exfiltrat|internal|callback.*manipul|secret.*leak|replay|forge"),
    "session": ("session management flaw with account impact: fixation, non-invalidation, or hijack proven",
                [r"session exists|cookie set|no impact"], r"fixation|not.*invalidat|hijack|concurrent|token.*reuse|logout.*fail.*impact"),
    "source-leak": ("source code or sensitive configuration exposed with security-relevant content (not just stack traces)",
                    [r"stack trace only|error page|version"], r"source code|\.git|\.env|credential|api.?key|password|secret|config.*exposed|backup"),
    "payment-logic": ("payment/billing logic flaw with real financial impact (not just UI inconsistency)",
                      [r"ui only|display|no financial"], r"negative|free|zero.*price|bypass.*pay|discount.*manipul|coupon.*reuse|refund.*abuse|race.*payment"),
    "ato": ("account takeover proven end-to-end: attacker gains full access to victim's account",
            [r"self|own account|no victim"], r"takeover|victim.*account|password.*reset.*hijack|session.*hijack|full.*access|login.*as"),
    "websocket": ("WebSocket vulnerability with real impact: injection, auth bypass, or data leak via WS",
                  [r"websocket exists|connection established|no impact"], r"inject|hijack|cross-site.*ws|unauthenticat|cswsh|origin.*bypass|sensitive.*data"),
    "mcp": ("MCP tool/server vulnerability: prompt injection, tool poisoning, or unauthorized action via MCP",
            [r"mcp exists|tool listed|no impact"], r"inject|poison|unauthorized|exfiltrat|tool.*call|rug.*pull|shadowing|cross-context"),
    "llm-ai": ("LLM/AI vulnerability with real impact: prompt injection leading to data leak or unauthorized action",
               [r"jailbreak only|filter bypass|no impact|chatbot"], r"inject|exfiltrat|data leak|unauthorized|system prompt|tool.*call|action.*taken"),
    "cloud-misconfig": ("cloud misconfiguration with real data exposure or privilege escalation (not just open port/service)",
                        [r"port open|service running|no data"], r"s3.*public|bucket.*list|credential|metadata|privilege|iam|role.*assum|data.*expos"),
    "api-misconfig": ("API misconfiguration with real security impact: auth bypass, mass data access, or privilege escalation",
                      [r"api exists|endpoint found|no impact"], r"unauthenticat|mass.*data|paginate.*all|rate.?limit.*bypass.*impact|method.*override|verb.*tamper"),
}

PER_CLASS.update({
    "mass-assignment": ("a restricted field changed server-side authorization or state",
                        [r"field accepted only|no role change"], r"role.*admin|is_admin|privilege|permission.*changed|mass assignment"),
    "password-reset": ("reset flow compromise proven on a second account or owned victim fixture",
                       [r"email received only|link returned only"], r"password.*changed|account takeover|token.*reus|host.*poison|reset.*hijack"),
    "grpc": ("unauthorized gRPC method/data access or state change",
             [r"reflection only|service listed|method listed"], r"unauthorized|other user|sensitive.*data|mutation|privilege"),
    "subdomain-takeover": ("dangling DNS plus attacker-controlled content on the affected hostname",
                           [r"dangling only|cname only|nxdomain only"], r"claimed|attacker-controlled|controlled content|takeover.*verified"),
    "nextjs": ("Next.js-specific bypass with protected data/action or code execution",
               [r"version only|middleware present"], r"bypass.*accepted|protected.*data|server action|rce|unauthorized"),
    "nodejs": ("Node.js-specific injection/auth bypass with a sensitive sink",
               [r"prototype modified only|stack only"], r"rce|xss|bypass|admin|extracted|unauthorized"),
    "laravel": ("Laravel-specific debug/auth/deserialization impact",
                [r"debug enabled only|version only"], r"rce|credential|secret|unauthorized|file contents|executed"),
    "springboot": ("Spring-specific actuator/injection impact",
                   [r"actuator exists|mappings only"], r"heapdump|credential|secret|rce|executed|unauthorized"),
    "aspnet": ("ASP.NET-specific authentication/deserialization impact",
               [r"viewstate present|version only"], r"machinekey|command output|rce|bypass|unauthorized"),
    "sharepoint": ("SharePoint-specific auth bypass, sensitive read, or code execution",
                   [r"ntlm only|version only|sharepoint detected"], r"toolshell|rce|bypass|sensitive.*data|command output"),
    "k8s": ("Kubernetes/Docker unauthorized workload, secret, or host impact",
            [r"api reachable|pod listed only"], r"exec|secret|token|host escape|unauthorized|created pod"),
    "container-escape": ("cross-tenant/host boundary violation with demonstrated access",
                         [r"container detected|socket exposed only"], r"host.*access|escape|other tenant|secret|exec"),
    "cicd": ("CI/CD command execution, secret exposure, or deployment impact",
             [r"workflow exists|self-hosted only"], r"command output|secret|artifact|deployed|pull_request_target.*executed"),
    "baas": ("backend-as-a-service unauthorized read/write with real data",
             [r"firebase config|api key only|rules shown only"], r"unauthorized.*(read|write)|other user|sensitive.*data|deleted|modified"),
    "desktop-macos": ("macOS desktop privileged action, credential access, or code execution",
                      [r"url scheme exists|electron only"], r"privileged|keychain|command output|executed|credential"),
    "desktop-windows": ("Windows desktop privileged action, credential access, or code execution",
                        [r"url protocol exists|electron only"], r"privileged|credential|command output|executed|system.*access"),
    "tls-network": ("demonstrated interception, spoofing, or downgrade impact",
                    [r"missing hsts|weak cipher only|certificate only"], r"intercepted|downgraded|spoofed|session.*captured|mitm.*reproduced"),
    "ntlm-info": ("anonymous NTLM challenge disclosing internal identity material",
                  [r"ntlm banner only|negotiate header only"], r"netbios|internal dns|domain name|forest|computer name|av_pairs"),
})

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
    (r"version disclosure|server banner|powered[- ]by", "version/banner disclosure without exploit"),
    (r"directory listing", "directory listing without sensitive data exposure"),
    (r"autocomplete|password.*clear", "autocomplete/password in cleartext (browser-level)"),
    (r"cookie without (secure|httponly) flag", "cookie flag missing without demonstrated exploit chain"),
    (r"text injection|content injection|html injection", "text/HTML injection without XSS (no script execution)"),
]

REQUIRED = ["vuln_class", "url", "title"]
PROOF_FIELDS = ["poc", "request", "response", "evidence", "steps"]


# ------- concrete fix guidance: what to ADD, per failed check (never just "don't submit") -------
def _fix_for(name, note, cls):
    """Actionable remediation for a failed check — the exact thing to add/do, class-aware."""
    if name == "has repro steps":
        return ("Add numbered steps a stranger can follow: exact URL + params, the account role used, "
                "what to click/send, and the before/after. e.g. '1) login as user A 2) POST /api/x with "
                "{...} 3) observe Y in the response'.")
    if name == "has PoC / evidence":
        return ("Attach the RAW request + response (Burp 'copy to file' or curl -i) showing the vuln "
                "firing, plus a screenshot. The response must show the impact data itself — a bare 200 "
                "or an error message is not proof.")
    if name == "has impact stated":
        return ("State WHO is affected and WHAT the attacker gets, in one sentence: e.g. 'any "
                "authenticated user can read any other user's invoices (PII: name, address, amount)'.")
    if name == "in scope":
        return "The URL host is outside the program scope — re-target an in-scope host; do not report this one."
    if name == "class is qualifying":
        return ("This class is on the program's NON-qualifying list — reporting it earns RTFS/N/A. "
                "Either chain it into a qualifying impact (e.g. use it for ATO) or hunt a qualifying class.")
    if name == "not an always-rejected class":
        return ("This pattern is always rejected as-is. The only way through: chain it to a demonstrated "
                "higher impact (e.g. self-XSS → stored XSS hitting other users) and show the full chain working.")
    if name.startswith("PoC minimum for"):
        per_cls = {
            "idor": "Create TWO accounts (A=victim, B=attacker). As A, create/note the object id. As B, "
                    "request A's id. Paste BOTH responses side-by-side with A's data highlighted in B's response.",
            "bola": "Same two-account proof as IDOR, at the object level: B receives an object owned by A.",
            "xss": "Show the payload EXECUTING in a victim-context page: screenshot of the alert/callback + "
                   "the unencoded payload in the response HTML. Reflection or &lt;encoding is not enough.",
            "ssrf": "Show the internal RESPONSE BODY (or an OOB callback with content) — a DNS pingback alone "
                    "is not accepted. Hit 169.254.169.254 or an internal host and paste what came back.",
            "sqli": "Extract something real (version(), current_user, a row) or show a clear boolean/time "
                    "difference (SLEEP(5) → 5s delay, n>=10 timings). An error message alone is not enough.",
            "rce": "Paste the command output (id / whoami / uname -a) as returned by the target.",
            "cors": "Show Origin reflected + Access-Control-Allow-Credentials:true AND a credentialed "
                    "cross-origin read working in a browser (fetch with credentials:'include').",
            "open-redirect": "Show the 3xx with Location: https://attacker — and if you claim token theft, "
                             "reproduce the full chain end-to-end.",
            "secret": "Prove the secret is VALID: use it (read-only) and show what it unlocks. Public "
                      "publishable keys (pk_live, maps, firebase config) are not findings.",
            "ssti": "Prove SERVER-side evaluation: {{7*7}} → 49 in the response, or read a server "
                    "config/class. In Angular, {{7*7}} rendering is client-side (CSTI), not SSTI.",
            "lfi": "Paste actual file contents returned (e.g. root:x:0:0 from /etc/passwd) — a 200 on a "
                   "traversal path is not enough.",
            "csrf": "Show a STATE-CHANGING action (email/password change) performed cross-site with the "
                    "victim's session — logout/login/cart CSRF is not accepted.",
            "xxe": "Show data exfiltrated via XXE (file contents) or SSRF proven via OOB callback with "
                   "response data — a DTD parsing error alone is not enough.",
            "nosqli": "Extract real data or show a clear boolean/timing difference proving injection — "
                      "an error message or stack trace alone is not enough.",
            "crlf": "Show the injected header in the HTTP response headers (not body). Paste the raw "
                    "response showing your injected Set-Cookie/Location header.",
            "deserialization": "Show code execution (command output) or dangerous object instantiation — "
                               "a theoretical gadget chain is not enough.",
            "cache-poison": "Show a DIFFERENT user receiving your poisoned response — poisoning your own "
                            "cache is not enough. Two sessions required.",
            "file-upload": "Show the uploaded file executing (RCE) or being served with a dangerous "
                           "content-type (XSS) — upload accepted alone is not enough.",
            "race-condition": "Show the state inconsistency (double spend, extra coupon, negative balance) "
                              "— parallel 200s alone are not enough.",
            "http-smuggling": "Show the desync: front-end and back-end interpret the request boundary "
                              "differently, and you can poison another user's request.",
            "prototype-pollution": "Show the polluted property reaching a security sink (XSS, RCE, auth "
                                   "bypass) — setting __proto__ alone is not enough.",
            "jwt": "Show a forged/modified token accepted by the server with privilege escalation — "
                   "decoding the JWT alone is not enough.",
            "saml": "Show authentication bypass or assertion forgery accepted — metadata exposure alone "
                    "is not enough.",
            "ldap": "Show data extraction or auth bypass via LDAP injection — an error alone is not enough.",
            "host-header": "Show security impact from injected Host header: password reset poisoning, "
                           "cache poisoning, or SSRF — reflection alone is not enough.",
            "dom-xss": "Show the DOM XSS executing in victim context — identifying source/sink potential "
                       "alone is not enough.",
            "pdf-ssrf": "Show internal data or OOB callback from PDF generation SSRF — the PDF being "
                        "generated alone is not enough.",
        }
        return per_cls.get(cls, "Add the proof that demonstrates real impact for this class (see the note).")
    if name == "severity supported by evidence":
        return ("Either lower the severity to match what you actually proved, or attach the stronger "
                "evidence (cross-account data / command output / metadata) that justifies it.")
    if name.startswith("dedup"):
        return ("This looks like a known duplicate. Only report if you can show a concrete differentiator: "
                "a new endpoint/param, a bypass of the original fix, or a stronger impact than the known report.")
    if name.startswith("disposition"):
        return ("The impact depends on a precondition you never demonstrate (e.g. possessing a victim "
                "session/id). Add the step that obtains it from an IN-SCOPE vector — XSS, CSRF, an enumerable/"
                "leaked id, an in-scope oracle — with it working in the PoC, or do not submit.")
    if name == "impact precondition is demonstrated (not hypothetical)":
        return ("Show HOW the attacker gets the victim's session/id: is the id sequential or returned by "
                "another in-scope endpoint? Is there an XSS/CSRF that grabs it? Add that step + proof.")
    if name.startswith("live reproduction"):
        return note or "Reproduce it live and paste the exact request/response that proves it."
    return "Address the note on this check, then re-verify."


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
        s = SCMOD.Scope(scope.get("in_scope", []), scope.get("out_of_scope", []),
                        path_restrictions=scope.get("path_restrictions", {}),
                        out_path_restrictions=scope.get("out_path_restrictions", {}))
        return s.in_scope_host(url)
    except Exception:  # noqa: BLE001
        return None


# ------- live reproduction: actually probe the vuln (READ-ONLY, in-scope only, no brute force) -------
_LIVE_LOCK = __import__("threading").Lock()
_SQL_ERR = re.compile(r"sql syntax|mysql|mariadb|postgres|psql|sqlite|ora-\d{4}|odbc|jdbc|"
                      r"unclosed quotation|unterminated string|syntax error.*sql", re.I)


def _probe_url_and_param(f):
    """The URL to probe + a guess at the injectable param (from the url query, else from the PoC)."""
    from urllib.parse import urlparse, parse_qsl
    url = f.get("url", "")
    for cand in [url] + re.findall(r"https?://[^\s\"')<>]+", str(f.get("poc", ""))):
        q = parse_qsl(urlparse(cand).query)
        if q:
            return cand, q[0][0]
    return url, None


def _xss_payload(f):
    m = re.search(r"(<[^\n>]{0,100}(?:script|svg|alert|onerror|img)[^\n>]{0,40}>?)", str(f.get("poc", "")), re.I)
    return (m.group(1) if m else '"><svg/onload=alert(1)>')[:120]


def _payload_core(payload):
    """The tag core used for the reflection check (the send payload may carry breakout prefixes)."""
    m = re.search(r"<[^\n>]+>?", payload)
    return (m.group(0) if m else payload).lower()


def live_check(f, program=None, base=DEFAULT_BASE, max_probes=4):
    """Try to REPRODUCE the finding with a few read-only GETs. Hard guards: https only, the host must
    be confirmed IN the program scope (no scope / out-of-scope => never probed), GET only, at most
    max_probes requests, one payload per class (no lists/brute force). Returns
    {attempted, probes, confirmed(True/False/None), note}."""
    from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
    out = {"attempted": False, "probes": [], "confirmed": None, "note": ""}
    url = (f.get("url") or "").strip()
    if not url.startswith("http"):
        out["note"] = "no URL to probe"
        return out
    scope = _load_scope(program or f.get("program"), base)
    if not scope:
        out["note"] = "no program scope — live check skipped (never probe unknown scope)"
        return out
    if _in_scope(url, scope) is not True:
        out["note"] = "URL not confirmed in-scope — live check skipped"
        return out
    try:
        import netget
    except Exception as e:  # noqa: BLE001
        out["note"] = f"prober unavailable: {e}"
        return out

    def _get(u):
        h = {"User-Agent": scope["user_agent"]} if scope.get("user_agent") else None
        with _LIVE_LOCK:                       # env is process-wide; keep set/probe/restore atomic
            saved = {k: os.environ.get(k) for k in ("HUNT_IMPERSONATE", "HUNT_PROXY")}
            if scope.get("impersonate"):
                os.environ["HUNT_IMPERSONATE"] = scope["impersonate"]
            if scope.get("proxy"):
                os.environ["HUNT_PROXY"] = scope["proxy"]
            try:
                return netget.get(u, headers=h, timeout=15)
            finally:
                for k, v in saved.items():
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    import vulncatalog as VC
    cls = VC.canonical_class(f.get("vuln_class"))
    purl, param = _probe_url_and_param(f)
    out["attempted"] = True

    def _add(name, u, st, txt, hd, signal=""):
        out["probes"].append({"name": name, "url": u[:200], "status": st,
                              "bytes": len(txt or ""), "signal": signal})

    # 1) baseline — is the endpoint even reachable, and does it need auth?
    st, txt, hd = _get(purl)
    if st == 0:
        out["note"] = f"endpoint unreachable ({hd.get('_error', '')[:80]}) — check the URL/host"
        _add("baseline", purl, st, txt, hd)
        return out
    _add("baseline", purl, st, txt, hd,
         "auth required" if st in (401, 403) else "")
    base_len = len(txt or "")

    # 2) one class-specific probe (single payload — no brute force)
    if cls == "xss" and param:
        payload = _xss_payload(f)
        q = urlencode([(param, payload)] + [(k, v) for k, v in parse_qsl(urlparse(purl).query) if k != param])
        u2 = urlunparse(urlparse(purl)._replace(query=q))
        st2, txt2, hd2 = _get(u2)
        if _payload_core(payload) in (txt2 or "").lower():
            out["confirmed"] = None
            out["note"] = f"payload reflected UNENCODED (HTTP {st2}) — detection only; browser execution is required"
            _add("xss-reflection", u2, st2, txt2, hd2, "payload reflected unencoded")
        elif re.search(r"&lt;|&gt;|&quot;", txt2 or ""):
            out["confirmed"] = False
            out["note"] = ("payload comes back HTML-ENCODED — not exploitable on this sink as-is. "
                           "Try another param/sink, an attribute-breakout payload, or a different context")
            _add("xss-reflection", u2, st2, txt2, hd2, "reflected encoded")
        else:
            if st2 != st or st2 in (401, 403, 429):
                out["note"] = (f"probe got HTTP {st2} vs baseline {st} — WAF/auth interference, "
                               "inconclusive; re-test in Burp and paste the real request/response")
                _add("xss-reflection", u2, st2, txt2, hd2, "inconclusive (blocked)")
            else:
                out["confirmed"] = False
                out["note"] = ("the claimed reflection does NOT reproduce live (param ignored or wrong "
                               "sink) — re-test in Burp, find the real reflecting param/context, and paste "
                               "the working request/response")
                _add("xss-reflection", u2, st2, txt2, hd2, "no reflection")
    elif cls == "open-redirect" and param:
        q = urlencode([(param, "https://example.com/")] + [(k, v) for k, v in parse_qsl(urlparse(purl).query) if k != param])
        u2 = urlunparse(urlparse(purl)._replace(query=q))
        st2, txt2, hd2 = _get(u2)
        loc = hd2.get("location", "")
        if st2 in (301, 302, 303, 307, 308) and "example.com" in loc:
            out["confirmed"] = True
            out["note"] = f"redirects to an external host (Location: {loc[:80]}) — live signal confirms it"
            _add("open-redirect", u2, st2, txt2, hd2, f"Location: {loc[:60]}")
        elif st2 != st or st2 in (401, 403, 429):
            out["note"] = (f"probe got HTTP {st2} vs baseline {st} — WAF/auth interference, inconclusive; "
                           "re-test in Burp")
            _add("open-redirect", u2, st2, txt2, hd2, "inconclusive (blocked)")
        else:
            out["confirmed"] = False
            out["note"] = (f"no external redirect (HTTP {st2}, Location: {loc[:60] or 'none'}) — "
                           "try bypasses (//host, /\\host, %2f%2f, .evil-suffix) or another param")
            _add("open-redirect", u2, st2, txt2, hd2, "no external redirect")
    elif cls == "sqli" and param:
        q = urlencode([(param, "'")] + [(k, v) for k, v in parse_qsl(urlparse(purl).query) if k != param])
        u2 = urlunparse(urlparse(purl)._replace(query=q))
        st2, txt2, hd2 = _get(u2)
        if _SQL_ERR.search(txt2 or ""):
            out["confirmed"] = None
            out["note"] = ("single quote triggers a DB error — detection only. EXTRACT data or prove a "
                           "time/boolean difference before treating this as reproduction")
            _add("sqli-error", u2, st2, txt2, hd2, "DB error on quote")
        else:
            out["note"] = ("no DB error on a quote — could still be blind; prove with SLEEP(5) timing "
                           "(n>=10) or boolean diff, and paste the timings")
            _add("sqli-error", u2, st2, txt2, hd2, "no error signal")
    else:
        # idor/ssrf/lfi/rce/... : can't be proven with one anonymous GET — say exactly what to capture
        if st in (401, 403):
            out["note"] = ("endpoint requires auth — reproduce it with your TWO accounts (A creates, B "
                           "accesses A's object) and paste both responses side-by-side")
        else:
            out["note"] = (f"endpoint reachable (HTTP {st}, {base_len}B). This class can't be confirmed "
                           "with an anonymous GET — attach the full request/response that proves the impact "
                           "(cross-account data / file contents / command output)")
    return out


def verify_finding(f, program=None, base=DEFAULT_BASE, live=False):
    checks, missing = [], []
    import vulncatalog as VC
    cls = VC.canonical_class(f.get("vuln_class"))
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
            if pat == r"rate.?limit|brute.?force|captcha" and cls in (
                    "2fa-bypass", "auth-bypass", "password-reset", "ato", "session", "api-misconfig"):
                continue
            if not re.search(r"chain|leads to|results in|account takeover|ato|rce|exfiltrat", blob):
                hard_reject = hard_reject or f"always-rejected: {why}"
            break
    add("not an always-rejected class", hard_reject is None, hard_reject or "")

    # 4b) RTFS / Informative disposition — ADVISORY only. It is a TEXT-heuristic (it cannot see your PoC), and
    # disposition itself already PASSES findings that show concrete impact, so a hold here is a NEEDS_FIXES
    # NOTE — never a hard DO_NOT_SUBMIT. A real, proven vuln stays reportable; only junk / out-of-scope /
    # non-qualifying hard-block. Rule: prove the vuln works with security impact -> it's reportable.
    try:
        import disposition as DP
        dres = DP.check(f, program=program or f.get("program"), base=base)
    except Exception as e:  # noqa: BLE001
        dres = {"verdict": "PASS", "reason": f"disposition gate unavailable ({e})"}
    held = dres.get("verdict") != "PASS"
    add("disposition (not RTFS / Informative)", not held,
        "" if not held else f"{dres.get('verdict')}: {dres.get('reason','')[:150]} "
        "(advisory — make the PoC explicit; NOT a block)")

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
        reproduction = f.get("reproduction") or {}
        methods = reproduction.get("tools") or ([reproduction.get("method")] if reproduction.get("method") else [])
        methods = [m for m in methods if m and m != "none"]
        add("independent reproduction (two tools for High/Critical)", len(set(methods)) >= 2,
            "" if len(set(methods)) >= 2 else "reproduce with two independent tools/transports; an LLM opinion is not a tool")

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

    # (RTFS / Informative disposition is handled once, as an advisory, in step 4b above — no hard block.)

    # 9) generic precondition check — the #1 RTFS cause: impact needs a victim secret the PoC never obtains
    _precond = re.compile(r"stolen session|obtain(?:s|ed|ing)? (?:a |the )?(?:victim'?s? )?(?:vendor |user )?session|"
                          r"cookie theft|session hijack|shared machine|physical access|\bmitm\b|man-in-the-middle|"
                          r"anyone who obtains|attacker who obtains|leaked (?:transaction|object|order|invoice) id")
    _proven = re.compile(r"document\.cookie|samesite\s*=\s*none|xss.{0,80}(executed|fired|exfiltrat)|"
                         r"cross-site form|csrf reproduced|in-scope (?:api|response|endpoint).{0,60}(?:uuid|id)|"
                         r"response (?:lists|returned) (?:another|other|victim)|enumerable|sequential id|"
                         r"demonstrated (?:a |the )?(?:way|method) to obtain|obtained from an in-scope")
    # Concrete proof (incl. a data/secret disclosure actually returned) OVERRIDES this heuristic, and a miss
    # is ADVISORY (NEEDS_FIXES) — never a hard DO_NOT_SUBMIT. A secondary/downstream mention of "session
    # hijacking" must not kill a finding whose PRIMARY impact is proven (e.g. an authed config dump).
    try:
        import disposition as _DPp
        _has_proof = bool(_DPp._PROOF_SHOWN.search(blob))
    except Exception:  # noqa: BLE001
        _has_proof = False
    if _precond.search(blob) and not _proven.search(blob) and not _has_proof:
        add("impact precondition is demonstrated (not hypothetical)", False,
            "impact leans on a precondition the PoC may not obtain — show how an attacker gets it "
            "(XSS/CSRF/enumerable id/in-scope oracle), or lead with the primary impact you DID prove "
            "(advisory — not a hard block)")

    # 10) LIVE reproduction — actually probe the vuln (read-only, in-scope only). A negative signal
    # (payload encoded / no redirect) fails the check with guidance; inconclusive (auth needed) never does.
    lv = None
    if live:
        try:
            lv = live_check(f, program=program or f.get("program"), base=base)
        except Exception as e:  # noqa: BLE001
            lv = {"attempted": False, "probes": [], "confirmed": None, "note": f"live check error: {e}"}
        if lv.get("attempted"):
            if lv["confirmed"] is True:
                add("live reproduction", True, lv["note"])
            elif lv["confirmed"] is False:
                add("live reproduction", False, lv["note"])
                missing.append("live-proof")
            else:
                add("live reproduction (inconclusive)", True, lv["note"])

    # READY must DEMONSTRATE the vuln (your rule: "try the vuln — if it works with impact, report it"), not
    # just describe it. Advisory only (a miss is NEEDS_FIXES, never a hard DO_NOT_SUBMIT): a real finding with
    # a request+response, a screenshot, or shown cross-account/exec/extraction proof passes; a pure hypothetical
    # ("attacker COULD, IF they had the cookie") with no artifact is held out of READY until it's shown working.
    try:
        import disposition as _DP
        _proof_re = _DP._PROOF_SHOWN
    except Exception:  # noqa: BLE001
        _proof_re = re.compile(r"cross-account|command output|/etc/passwd|union select|stole the (session|token|cookie)", re.I)
    # GENERIC, class-agnostic proof-artifact detection (NOT tuned to any report): the finding actually SHOWS a
    # server response/output or attaches evidence — request+response, a response status/JSON body, a HAR,
    # a screenshot/video, or any uploaded file. Together with live reproduction (step 10) and the deep model
    # triage, this is the DYNAMIC 'is it demonstrated' signal; the regex above is just one way to satisfy it.
    _artifact = bool(
        (f.get("request") and f.get("response")) or f.get("response") or f.get("_images") or f.get("_files_dir")
        or re.search(r"HTTP/\d(?:\.\d)?\s+\d{3}|\"data\"\s*:|^\s*[\[{]", blob, re.I | re.M)
        or re.search(r"\bresponse\.(?:txt|json|har)\b|\.har\b|screenshot|burp|\.(?:png|jpe?g|gif|mp4|webm)\b", blob, re.I))
    demonstrated = bool(_proof_re.search(blob) or _artifact)
    add("demonstrated (concrete proof, not hypothetical)", demonstrated,
        "" if demonstrated else "show it FIRING: attach the request+RESPONSE (or a screenshot / HAR / the "
        "returned data). Prose like 'an attacker could…' with no response or artifact is not proof.")

    fails = [c for c in checks if not c["pass"]]
    for c in fails:                                  # every failure comes with the exact fix
        c["fix"] = _fix_for(c["check"], c.get("note", ""), cls)
    score = round(100 * (len(checks) - len(fails)) / max(1, len(checks)))
    if hard_reject or insc is False:
        verdict = "DO_NOT_SUBMIT"
    elif fails:
        verdict = "NEEDS_FIXES"
    else:
        verdict = "READY"
    out = {"verdict": verdict, "score": score, "program": program or f.get("program"),
           "vuln_class": cls, "severity": sev, "url": url,
           "checks": checks, "failed": [c["check"] for c in fails], "missing": missing,
           "how_to_fix": [{"check": c["check"], "fix": c["fix"]} for c in fails],
           "dedup": dedup, "accept": verdict == "READY"}
    if lv:
        out["live"] = lv
    out["summary"] = _summarize(out)
    return out


def deep_opinion(f, det, program=None, base=DEFAULT_BASE, timeout=180):
    """Optional strict LLM triager opinion (cursor-agent). Returns dict or None."""
    try:
        import agent as A
        scope = _load_scope(program or f.get("program"), base) or {}
        task = _triager_task(f, det, scope, base)
        r = A.run_agent(task, context=None, timeout=timeout, attempts=1)
        js = A.extract_json(r.get("result", "")) if hasattr(A, "extract_json") else None
        if isinstance(js, dict) and js.get("verdict"):
            js["model"] = r.get("model")
            return js
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:120]}
    return None


def _triager_task(f, det, scope, base=DEFAULT_BASE):
    # everything the operator uploaded reaches the triager: full finding JSON (text + scripts already
    # merged into evidence) AND the on-disk dir so the agent can READ the images/scripts itself.
    files_dir = f.get("_files_dir")
    names = ", ".join(f.get("_file_names") or [])
    files_note = (f"\nUPLOADED EVIDENCE FILES are saved at: {files_dir} ({names}). "
                  "READ them with your file tools — images show the PoC, scripts are the exploit — "
                  "and factor what you see into the verdict.\n" if files_dir else "")
    eng = os.path.dirname(os.path.abspath(__file__))
    program = f.get("program") or (scope.get("name") if isinstance(scope, dict) else "") or ""
    in_scope = scope.get("in_scope", []) if isinstance(scope, dict) else []
    ua = scope.get("user_agent") if isinstance(scope, dict) else None
    intrusive = os.environ.get("HUNT_INTRUSIVE") == "1"
    # ACTIVE reproduction (generic, any class/target): TRY the vuln, don't judge the prose alone.
    action = ("You MAY create test accounts, log in, and perform STATE-CHANGING actions on your OWN test "
              "accounts (the write / email-change / etc. that proves impact) — do what it takes to confirm it. "
              "HARD LIMITS: in-scope only, NO brute-force, NO destructive/DoS/mass-exploitation (prove it ONCE, "
              "then STOP)." if intrusive else
              "Read-only, no writes/destructive actions, no brute force.")
    if in_scope:
        scope_line = f"IN-SCOPE hosts ONLY: {', '.join(in_scope[:30])}."
    else:
        scope_line = (f"SCOPE NOT pre-loaded — LOOK IT UP FIRST: web-search / fetch this program's official "
                      f"bug-bounty scope ('{program}' on HackerOne / Bugcrowd / Intigriti, or the vendor's "
                      "security.txt / responsible-disclosure page), CONFIRM the finding's target host is in that "
                      "scope, and note the source. If the target is OUT of scope or the program runs no bounty "
                      "-> DO_NOT_SUBMIT. Only send requests to hosts you've confirmed in-scope.")
    repro = (
        "\nACTIVELY REPRODUCE — do NOT decide from the write-up alone. This is an AUTHORIZED engagement. "
        + scope_line + " " + action
        + (f" Send EVERY request with User-Agent: '{ua}'." if ua else "")
        + " RE-RUN the PoC with REAL requests and judge from the LIVE response you observe:\n"
        f"  - curl, or the harness fetch that carries the stored login + bypasses edge gating:\n"
        f"    `python3 {eng}/netget.py GET \"<url>\" --as A`  (POST: `... POST \"<url>\" '<body>' --as A`; victim: `--as B`).\n"
        f"  - cross-account IDOR/BOLA: `python3 {eng}/authz.py diff --slug {program} --url \"<A-owned url>\"`.\n"
        f"  - need an account (or a second one): `python3 {eng}/identity.py new --program {program}`.\n"
        "If you REPRODUCE the vuln with real, exploitable security impact -> REAL BUG (real_bug:true, "
        "reproduced:true). If you can't reach/obtain what the impact needs -> reproduced:\"inconclusive\". "
        "If the live response disproves the claim -> real_bug:false.\n")
    auth = ""                                      # inject the stored login so behind-login findings reproduce
    try:
        import authsession as _AS
        sess = _AS.load(program, base=base)
        if _AS.valid(sess) and f.get("url"):
            auth = _AS.auth_block(sess, f.get("url"))
    except Exception:  # noqa: BLE001
        pass
    return (
        "You are a STRICT bug-bounty triager who REPRODUCES findings, not just reads them. Decide if this "
        "draft finding is a REAL, submittable bug. Be harsh: reflection-only, error-only, no-impact, "
        "theoretical, out-of-scope, non-qualifying, or an impact that depends on a victim secret the PoC "
        "never obtains (a session/id/token) = REJECT."
        + repro + auth +
        f"\n\nFINDING:\n{json.dumps(f, indent=2)[:24000]}\n{files_note}\n"
        f"PROGRAM non-qualifying: {scope.get('non_qualifying', [])[:20]}\n"
        f"PROGRAM qualifying classes: {scope.get('qualifying_classes', [])}\n"
        f"Deterministic pre-check: verdict={det['verdict']}, failed={det['failed']}\n\n"
        "Reply ONLY JSON: {\"verdict\":\"READY|NEEDS_FIXES|DO_NOT_SUBMIT\","
        "\"real_bug\":true|false,\"reproduced\":true|false|\"inconclusive\","
        "\"reasons\":[...],\"missing\":[...],\"severity_opinion\":\"...\"}")


def _cleanup(paths=(), session_ids=()):
    """Verify is verify-only: after the review, remove the upload dir AND the ephemeral triager chat
    sessions it opened. Pooled/running hunt sessions are never touched (sessions.drop_ids guards)."""
    import shutil
    for p in paths:
        try:
            if p and os.path.isdir(p):
                shutil.rmtree(p)
        except OSError:
            pass
    if session_ids:
        try:
            import sessions as SESS
            SESS.drop_ids(session_ids)
        except Exception:  # noqa: BLE001
            pass


def _pool_models():
    import agent
    return agent._pool_models()


def deep_opinion_all(f, det, program=None, base=DEFAULT_BASE, timeout=None, max_models=4):
    """Run the strict triager across EACH pool model IN PARALLEL and combine — the STRICTEST verdict
    wins, so a single lenient model can't green-light an RTFS/NA/Info report. Takes its time: each model
    gets a generous timeout and is never cut off early. Returns {verdict, opinions, models_run, agreement}."""
    import agent as A
    from concurrent.futures import ThreadPoolExecutor
    scope = _load_scope(program or f.get("program"), base) or {}
    task = _triager_task(f, det, scope, base)
    # so the models' ACTIVE reproduction (netget --as A / curl) carries the stored login + program UA
    _prog = program or f.get("program") or (scope.get("name") if isinstance(scope, dict) else None)
    if _prog:
        os.environ["HUNT_TARGET_SLUG"] = str(_prog)
    if isinstance(scope, dict) and scope.get("user_agent"):
        os.environ["HUNT_USER_AGENT"] = scope["user_agent"]
    models = _pool_models()[:max_models] or [None]
    per_model_timeout = timeout or int(os.environ.get("HUNT_VERIFY_MODEL_TIMEOUT", "300"))

    def _one(m):
        try:
            r = A.run_agent(task, context=None, model=m, timeout=per_model_timeout, attempts=1)
            sid = r.get("session_id")
            js = A.extract_json(r.get("result", "")) if hasattr(A, "extract_json") else None
            if isinstance(js, dict) and js.get("verdict"):
                js["model"] = r.get("model") or m
                if sid:
                    js["session_id"] = sid
                return js
            out = {"model": m, "error": "no verdict"}
            if sid:
                out["session_id"] = sid
            return out
        except Exception as e:  # noqa: BLE001
            return {"model": m, "error": str(e)[:100]}

    with ThreadPoolExecutor(max_workers=len(models)) as ex:
        opinions = list(ex.map(_one, models))
    verdicts = [o["verdict"] for o in opinions if o.get("verdict") in _VERDICT_ORDER]
    final = max(verdicts, key=lambda v: _VERDICT_ORDER[v]) if verdicts else None
    # REAL BUG = a model actually REPRODUCED it with impact AND no model rejected it (strictest != reject).
    real_bug = bool(final and final != "DO_NOT_SUBMIT"
                    and any(o.get("real_bug") is True for o in opinions))
    reproduced = [o.get("reproduced") for o in opinions if o.get("reproduced") not in (None, "")]
    return {"verdict": final, "real_bug": real_bug, "reproduced": reproduced, "opinions": opinions,
            "models_run": [o.get("model") for o in opinions],
            "session_ids": [o["session_id"] for o in opinions if o.get("session_id")],
            "agreement": (len(set(verdicts)) == 1) if verdicts else None}


# ------- secure file intake (uploaded report + evidence) -------
# scripts are TEXT here (captured for the triager to read) — they are stored chmod 600, never
# executed or served, and deleted right after the verify run.
ALLOWED_TEXT = {".md", ".txt", ".json", ".log", ".har", ".csv", ".xml", ".yaml", ".yml", ".http", ".nb",
                ".py", ".sh", ".bash", ".js", ".ts", ".php", ".rb", ".pl", ".ps1", ".java", ".go",
                ".html", ".htm", ".css", ".sql", ".ini", ".conf", ".cfg", ".env", ".burp", ".sm"}
ALLOWED_BIN = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".apk", ".ipa"}
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
MAX_TEXT_PER_FILE = 60000          # chars of each text/script file forwarded to the triager
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
            texts.append(f"--- {name} ---\n" + raw.decode("utf-8", "ignore")[:MAX_TEXT_PER_FILE])
        else:
            images += 1
    return {"saved": saved, "rejected": rejected, "text": "\n".join(texts),
            "images": images, "dir": root if saved else None}


def _summarize(det, opinion=None):
    """One short human brief: the verdict, why, what to do next — and the exact fixes to add."""
    v = det.get("verdict", "NEEDS_FIXES")
    fails = [c for c in det.get("checks", []) if not c.get("pass")]
    reasons = [f"{c['check']}" + (f" ({c['note']})" if c.get("note") else "") for c in fails]
    fixes = [c["fix"] for c in fails if c.get("fix")]
    if v == "READY":
        why = "All checks pass: real PoC, repro steps, demonstrated impact, in-scope, qualifying class, not a duplicate."
        nxt = "Ready to report. Keep the two-account / impact evidence attached and redact any PII."
    elif v == "DO_NOT_SUBMIT":
        why = "Would likely be closed (RTFS / Informative / N/A): " + ("; ".join(reasons) if reasons else "fails a hard gate.")
        nxt = ("Do NOT submit as-is. " + (fixes[0] if fixes else
               "Prove the missing precondition (how the attacker gets the victim's session/id) or pick a stronger finding."))
    else:
        why = "Close, but not submittable yet: " + ("; ".join(reasons) if reasons else "some checks need attention.")
        nxt = ("Add what's missing, then re-verify: " + " | ".join(fixes[:3])) if fixes else \
              "Fix the failed checks above, then re-verify."
    if opinion and opinion.get("verdict") and opinion.get("verdict") != det.get("verdict"):
        why += f" Expert review was stricter ({opinion['verdict']})."
    return {"verdict": v, "why": why, "next": nxt, "how_to_fix": fixes}


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
    (r"business logic", "business-logic"),
    (r"information disclosure|info(?:rmation)? ?leak|sensitive (?:data|config\w*|information)\s+"
     r"(?:is |are |was |were )?(?:expos|disclos|leak|accessible)|internal (?:data|config\w*|infrastructure|endpoint)"
     r".{0,30}(?:expos|disclos|accessible|dump|leak)|exposes? .{0,40}(?:internal|infrastructure|"
     r"sensitive|credential|secret|private)", "info-leak"),
    (r"\bssrf\b|server.?side request|xspa", "ssrf"),
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
    """Grab the body under a heading like 'Steps to reproduce' until the next heading of the SAME or
    SHALLOWER level. Deeper sub-headings (e.g. '### 1.', '### 2.' under a '## Steps to Reproduce') are PART
    of the section — stopping at them was dropping numbered repro steps and failing 'has repro steps'."""
    kset = [k.lower() for k in keys]
    out, cap, cap_level = [], False, 0
    for ln in (text or "").splitlines():
        m = re.match(r"^\s*(#{1,6})\s", ln)
        colon = (0 < len(ln.strip()) < 42 and ln.strip().endswith(":"))
        head = bool(m) or colon
        level = len(m.group(1)) if m else (99 if colon else 0)   # deeper # => bigger level; colon = deepest
        label = ln.strip().lstrip("#").strip().rstrip(":").strip().lower()
        if cap and head and level <= cap_level and label not in kset:
            break
        if not cap and head and any(label == k or label.startswith(k) for k in kset):
            cap = True
            cap_level = level
            continue
        if cap:
            out.append(ln)
    return "\n".join(out).strip()[:4000]


def _url_from_http_block(text):
    """Build the target URL from an HTTP request block (a 'Host:' header + the request line's path). The
    PoC's real target is usually written as a raw request, NOT a bare https:// URL — so the naive URL grab
    picks an evidence/docs link instead (e.g. a docs.google.com URL quoted in the findings). Returns ''
    when there is no request block."""
    host = _first(text, [r"^\s*Host:\s*([A-Za-z0-9.\-]+)"])
    if not host:
        return ""
    path = _first(text, [r"^\s*(?:GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+(/\S*)\s+HTTP"]) or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{host}{path}"


def extract_finding(text):
    """Best-effort parse of a report into {vuln_class,severity,url,title,steps,poc,impact}. Only non-empty."""
    t = text or ""
    low = t.lower()
    f = {}
    f["title"] = _first(t, [r"^\s*#\s*(.+)$", r"^\s*title\s*[:\-]\s*(.+)$", r'"title"\s*:\s*"([^"]+)"'])[:160]
    # prefer an explicit URL/Target line, THEN the PoC request block's Host (the real target), and only
    # fall back to the first bare https:// link (which is often an evidence/docs URL, not the target).
    f["url"] = (_first(t, [r"^\s*(?:url|affected|endpoint|target)\s*[:\-]\s*(https?://\S+)",
                           r'"url"\s*:\s*"([^"]+)"'])
                or _url_from_http_block(t)
                or _first(t, [r"(https?://[^\s\"')<>]+)"]))
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
    pc.add_argument("--live", action="store_true", help="probe the vuln read-only (in-scope only)")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    f = json.loads(sys.stdin.read()) if a.stdin else json.load(open(os.path.expanduser(a.file)))
    out = verify_finding(f, program=a.program, base=a.base, live=a.live)
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
        {"name": "exploit.py", "b64": _b64.b64encode(b"import requests  # PoC script").decode()},      # script -> captured as TEXT
        {"name": "x.exe", "b64": _b64.b64encode(b"MZ").decode()},                             # bad type -> reject
        {"name": "big.txt", "b64": _b64.b64encode(b"A" * (MAX_FILE + 1)).decode()},           # oversized -> reject
        {"name": "shot.png", "b64": _b64.b64encode(b"\x89PNG\r\n\x1a\n").decode()},           # image
    ]
    ing = ingest_files(files, program="acme-up", base=bse)
    saved = [s["name"] for s in ing["saved"]]
    rej = " ".join(r["name"] + ":" + r["reason"] for r in ing["rejected"])
    assert "report.md" in saved and "shot.png" in saved, saved
    assert "evil.md" in saved, saved                    # traversal collapsed to basename, stored IN the dir
    assert "exploit.py" in saved and "PoC script" in ing["text"], saved   # scripts reach the triager as text
    assert "x.exe" in rej and "big.txt" in rej, rej
    assert "cross-account" in ing["text"] and ing["images"] == 1, ing
    # traversal defeated: nothing written outside the upload dir
    import glob as _g
    for p in _g.glob(bse + "/**", recursive=True):
        assert os.path.isdir(p) or "verify-uploads" in p, p
    # 5) combined verdict = stricter of gate + expert opinion
    assert combine_verdict({"verdict": "READY"}, {"verdict": "DO_NOT_SUBMIT"}) == "DO_NOT_SUBMIT"
    assert combine_verdict({"verdict": "NEEDS_FIXES"}, {"verdict": "READY"}) == "NEEDS_FIXES"

    # 5b) every failed check carries a concrete fix + the summary lists how_to_fix
    assert all("fix" in c for c in rb["checks"] if not c["pass"]), rb
    assert rb.get("how_to_fix") and rb["summary"].get("how_to_fix"), rb.get("summary")
    fixes_txt = " ".join(str(x) for x in rb["summary"]["how_to_fix"]).lower()
    assert "chain" in fixes_txt or "account" in fixes_txt, fixes_txt

    # 5c) LIVE CHECK — offline, mocked prober. No scope => never probes. In-scope XSS: unencoded =>
    # confirmed; encoded => negative signal + fix guidance. Open-redirect => Location signal.
    import types as _T
    fake = _T.ModuleType("netget")
    calls = []
    def _fake_get(u, headers=None, timeout=15, **kw):
        calls.append(u)
        if "payload" in u or "svg" in u:
            return 200, "<html>&lt;svg/onload=alert(1)&gt;</html>", {}          # encoded reflection
        return 200, "<html>search results</html>", {"server": "test"}
    fake.get = _fake_get
    sys.modules["netget"] = fake
    try:
        import targets as _TG
        bse2 = _tf.mkdtemp()
        os.makedirs(os.path.join(bse2, "_targets"))
        json.dump({"program": "acme-live", "in_scope": ["app.example.com"], "out_of_scope": []},
                  open(os.path.join(bse2, "_targets", "acme-live.json"), "w"))
        xss = {"vuln_class": "xss", "url": "https://app.example.com/search?q=test",
               "title": "t", "poc": '"><svg/onload=alert(1)> reflects'}
        lv = live_check(xss, program="acme-live", base=bse2)
        assert lv["attempted"] and lv["confirmed"] is False and "encoded" in lv["note"].lower(), lv
        # unencoded reflection is a detection signal, not proof of execution
        fake.get = lambda u, headers=None, timeout=15, **kw: (200, '..."><svg/onload=alert(1)>...', {})
        lv2 = live_check(xss, program="acme-live", base=bse2)
        assert lv2["confirmed"] is None and "execution" in lv2["note"], lv2
        # no scope => never touched
        lv3 = live_check(xss, program=None, base=bse2)
        assert not lv3["attempted"] and "skipped" in lv3["note"], lv3
        # wired into verify_finding: negative live signal fails the check with a fix attached
        rlive = verify_finding(xss, program="acme-live", base=bse2, live=True)
        lc = [c for c in rlive["checks"] if c["check"].startswith("live reproduction")]
        assert lc and rlive.get("live", {}).get("attempted"), rlive.get("live")
    finally:
        sys.modules.pop("netget", None)
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
