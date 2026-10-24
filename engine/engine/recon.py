#!/usr/bin/env python3
"""
recon.py — deterministic SPA-aware attack-surface recon.

Agent-driven recon times out on real SPAs: every path returns the app shell, so
"crawling" finds nothing and the model burns its budget. The real surface lives in
the JavaScript bundles (the app references its own API routes / backend hosts). That
extraction is mechanical, so we do it in CODE — no LLM in the find-step:

  fetch seed HTML + robots/sitemap  ->  pull same-origin JS bundles  ->  regex-mine
  endpoints (relative /api routes, absolute backend hosts, forms, Next.js data)  ->
  scope-filter  ->  deterministic vuln-class heuristic

This is exactly the technique that surfaces a SPA's real API endpoints by hand (e.g. an
unauthenticated chat/LLM route buried in a bundle). Classification is a cheap keyword
heuristic (the agent is reserved for the HUNT phase, where judgment is needed).

stdlib-only fallback; uses `requests` if available (gzip/redirects handled cleanly).
"""
import os
import re
from shutil import which
from urllib.parse import urljoin, urlparse


def _tool_env():
    """Return env dict with ~/go/bin in PATH for Go recon tools."""
    env = os.environ.copy()
    gobin = os.path.expanduser("~/go/bin")
    if gobin not in env.get("PATH", ""):
        env["PATH"] = gobin + ":" + env.get("PATH", "")
    return env


_TOOL_ENV = _tool_env()

# Default browser UA; a per-target override comes from HUNT_USER_AGENT (set by the engine from the
# scope's user_agent), so recon traffic carries a program's required SOC tag.
_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _ua():
    return os.environ.get("HUNT_USER_AGENT") or _UA


def _impersonating():
    # route recon through netget when: edge-gated (TLS/proxy) OR an authenticated identity is set
    return bool(os.environ.get("HUNT_IMPERSONATE") or os.environ.get("HUNT_PROXY")
                or os.environ.get("HUNT_RECON_IDENT"))


def _get_impersonate(url, timeout=20):
    import netget
    current = url
    for _ in range(6):
        code, text, hdrs = netget.get(current, timeout=timeout,
                                      ident=os.environ.get("HUNT_RECON_IDENT") or None)
        clean = {k: v for k, v in (hdrs or {}).items() if not k.startswith("_")}
        if code == 0:
            return "", url, clean
        location = (hdrs or {}).get("location", "")
        if code not in (301, 302, 303, 307, 308) or not location:
            return text, current, clean
        if (hdrs or {}).get("_redirect_blocked"):
            return "", url, clean
        current = urljoin(current, location)
    return "", url, {}

try:
    import requests
    _SESS = requests.Session()
    _SESS.headers["User-Agent"] = _UA

    def _get(url, timeout=20):
        if _impersonating():
            return _get_impersonate(url, timeout)
        try:
            r = _SESS.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": _ua()})
            return r.text, r.url, {k.lower(): v for k, v in r.headers.items()}
        except Exception:
            return "", url, {}
except ImportError:                          # stdlib fallback
    import gzip
    import urllib.request

    def _get(url, timeout=20):
        if _impersonating():
            return _get_impersonate(url, timeout)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _ua(), "Accept-Encoding": "gzip"})
            r = urllib.request.urlopen(req, timeout=timeout)
            data = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            return data.decode("utf-8", "replace"), r.geturl(), {k.lower(): v for k, v in r.headers.items()}
        except Exception:
            return "", url, {}

JS_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
REL_API = re.compile(
    r'''["'`](/(?:api|rest|graphql|v\d[\w.]*|auth|oauth|users?|account|admin|internal|webhook|'''
    r'''upload|download|files?|proxy|fetch|search|query|email|chat|ai|llm|gateway|service|'''
    r'''session|token|export|import|report|invoice|order)[A-Za-z0-9/_.\-]*)["'`]''')
ABS_URL = re.compile(r'https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9/_.\-]*)?')
NEXT_DATA = re.compile(r'/_next/data/[A-Za-z0-9/_.\-]+')
FORM_BLOCK = re.compile(r'<form[\s\S]{0,600}?</form>', re.I)
FORM_ACTION = re.compile(r'action=["\']([^"\']*)["\']', re.I)
INPUT_NAME = re.compile(r'name=["\']([^"\']+)["\']', re.I)

# third-party / framework noise to exclude from "absolute backend host" mining
NOISE = re.compile(
    r'w3\.org|schema\.org|googleapis|gstatic|fonts?\.|sentry|google-?analytics|googletagmanager|'
    r'cloudflare|jsdelivr|unpkg|npmjs|github\.com|mozilla|react\.dev|nextjs\.org|vimeo|'
    r'example\.(com|org)|doubleclick|hotjar|segment|intercom|facebook|linkedin|twitter|youtube', re.I)

# an item is real attack surface (vs. a marketing/content page) if its path looks like an
# API/auth/file route, OR it carries a query parameter, OR it's a form submission.
API_HINT = re.compile(
    r'/(api|rest|graphql|gql|v\d[\w.]*|internal|webhook|auth|oauth|token|sso|saml|login|signin|'
    r'register|upload|download|admin|proxy|fetch|gateway|service|session|export|import|search|'
    r'query|user|users|account|order|invoice|file|files|report|_next/data)(/|$)', re.I)

# Browser capture includes top-level navigations, challenge machinery, and brochure pages alongside
# XHR/fetch. Those are not API surface and otherwise receive a discovery/ranking bonus downstream.
BROWSER_NOISE = re.compile(
    r'^/cdn-cgi/challenge-platform(?:/|$)|'
    r'/(?:blog|pricing|help|about|contact|careers?|press|news(?:room)?|legal|terms|privacy|cookies?|'
    r'features?|resources?|customer-stories|events?|webinars?|academy|community|company|solutions?)'
    r'(?:/|$)', re.I)


def _testable(item):
    u = item.get("url", "")
    return bool(API_HINT.search(urlparse(u).path)) or "?" in u or \
        item.get("source") == "form" or bool(item.get("param"))


def _browser_api_request(req):
    """Keep runtime API calls, not page navigation, assets, CDN challenges, or marketing paths."""
    url = (req.get("url") or "").split("#", 1)[0]
    path = urlparse(url).path or "/"
    if req.get("type") not in ("xhr", "fetch"):
        return False
    if BROWSER_NOISE.search(path) or is_static_asset(url):
        return False
    return _testable({"url": url, "source": "browser"})


# static assets / downloadable files — never an injection/IDOR target on their own. (A secret leaked
# INSIDE a .js bundle is still kept: that item carries source="secret", handled by the caller.)
STATIC_EXT = re.compile(
    r'\.(?:png|jpe?g|gif|webp|svg|ico|bmp|tiff?|avif|heic|'
    r'css|js|mjs|cjs|map|woff2?|ttf|otf|eot|'
    r'mp4|webm|ogv|ogg|mp3|wav|flac|m4a|avi|mov|wmv|mkv|'
    r'pdf|zip|gz|tgz|bz2|tar|rar|7z|dmg|pkg|exe|msi|apk|'
    r'doc|docx|xls|xlsx|ppt|pptx|csv)(?:$|[?#])', re.I)


def is_static_asset(url):
    return bool(STATIC_EXT.search(urlparse(str(url or "")).path))


def is_concrete_target(url):
    """True iff `url` is something we can actually hit with curl as a single concrete target.
    Robots/scope GLOB patterns (/api/*, /*?*builder.preview*, */search?*) and static assets are
    NOT concrete targets — testing them wastes a hunt step and always yields 'nothing'."""
    u = str(url or "")
    if not u or "://" not in u:
        return False
    if "*" in u:                 # literal glob from a robots.txt Disallow or a scope pattern
        return False
    if re.match(r'^/cdn-cgi/challenge-platform(?:/|$)', urlparse(u).path or "/", re.I):
        return False
    if is_static_asset(u):
        return False
    return True


def _mine(text, found_rel, found_abs):
    for m in REL_API.findall(text):
        found_rel.add(m)
    for m in NEXT_DATA.findall(text):
        found_rel.add(m)
    for m in ABS_URL.findall(text):
        if not NOISE.search(m):
            found_abs.add(m.rstrip('.,);"\''))


# high-signal secret patterns (subset of the offensive-osint catalog) for JS-bundle scanning
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("Google/Firebase API key", re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ("Anthropic key", re.compile(r'\bsk-ant-[0-9A-Za-z\-]{20,}\b')),
    ("OpenAI key", re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b')),
    ("Slack token", re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b')),
    ("GitHub token", re.compile(r'\bgh[pousr]_[0-9A-Za-z]{36,}\b')),
    ("Stripe live key", re.compile(r'\bsk_live_[0-9A-Za-z]{24,}\b')),
    ("Twilio account SID", re.compile(r'\bAC[0-9a-f]{32}\b')),
    ("Private key block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----')),
    ("JWT", re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("EmailJS service/template id", re.compile(r'\b(?:service|template)_(?=[a-z0-9]*[0-9])[a-z0-9]{6,}\b')),
    ("Hardcoded secret assignment", re.compile(
        r'(?:api[_\-]?key|apikey|client[_\-]?secret|access[_\-]?token|auth[_\-]?token|publicKey|user_id)'
        r'["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{12,})["\']', re.I)),
]
# documentation/placeholder values to ignore
_SECRET_NOISE = re.compile(r'EXAMPLE|YOUR_|XXXX|\.\.\.|<[^>]+>|process\.env|import\.meta', re.I)


def scan_secrets(text, url):
    """Return [{type, url, redacted}] for secrets exposed in client-side text. Values redacted."""
    out, seen = [], set()
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text or ""):
            tok = m.group(0)
            window = (text[max(0, m.start() - 12):m.end() + 12])
            if _SECRET_NOISE.search(tok) or _SECRET_NOISE.search(window):
                continue
            if tok in seen:
                continue
            seen.add(tok)
            red = tok if len(tok) <= 10 else f"{tok[:6]}…{tok[-4:]}"
            out.append({"type": label, "url": url, "redacted": red})
    return out


def spa_recon(scope, seeds=None, max_js=20, interesting_only=True, log=print):
    """Deterministically map the in-scope surface. Returns (surface_items, oos_hosts).
    seeds: explicit seed URLs (e.g. OSINT-discovered live hosts); defaults to scope.seeds.
    interesting_only filters out marketing/content pages, keeping real attack surface."""
    # Relative routes retain the origin of the HTML/JS that disclosed them. A shared relative path
    # can legitimately exist on several seeds; binding everything to the first seed loses that surface.
    found_rel, found_abs, forms, js_urls, secrets = set(), set(), [], set(), []
    for seed in (seeds or scope.seeds):
        if not scope.in_scope_host(seed):
            log(f"recon: seed {seed} not in scope — skip"); continue
        html, final, hdrs = _get(seed)
        base = f"{urlparse(final).scheme}://{urlparse(final).netloc}"
        log(f"recon: fetched {seed} ({len(html)} bytes, server={hdrs.get('server','?')})")
        for p in ("/robots.txt", "/sitemap.xml"):
            t, _, _ = _get(base + p)
            for a, b in re.findall(r'(?:Allow|Disallow):\s*(\S+)|<loc>([^<]+)</loc>', t):
                pp = a or b
                if pp:
                    found_rel.add((base, pp if pp.startswith('/') else (urlparse(pp).path or '/')))
        rel = set()
        _mine(html, rel, found_abs)
        found_rel.update((base, route) for route in rel)
        secrets += scan_secrets(html, final)
        for m in JS_SRC.findall(html):
            ju = urljoin(base, m)
            if scope.in_scope_host(ju):
                js_urls.add(ju)
        for fm in FORM_BLOCK.findall(html):
            act = FORM_ACTION.search(fm)
            forms.append({"action": urljoin(base, act.group(1)) if act else seed,
                          "params": INPUT_NAME.findall(fm)})

    for ju in list(js_urls)[:max_js]:
        js, _, _ = _get(ju)
        if js:
            rel = set()
            _mine(js, rel, found_abs)
            ju_origin = f"{urlparse(ju).scheme}://{urlparse(ju).netloc}"
            found_rel.update((ju_origin, route) for route in rel)
            secrets += scan_secrets(js, ju)
    # dedup secrets by (type, redacted)
    _seen = set()
    secrets = [s for s in secrets if not (s["type"], s["redacted"]) in _seen
               and not _seen.add((s["type"], s["redacted"]))]
    log(f"recon: mined {len(found_rel)} route(s), {len(found_abs)} absolute url(s), "
        f"{len(forms)} form(s), {len(secrets)} secret(s) from {len(js_urls)} JS bundle(s)")
    for s in secrets:
        log(f"recon:   🔑 SECRET {s['type']} = {s['redacted']} in {s['url']}")

    items, oos = [], set()
    for origin, rel in sorted(found_rel):
        url = rel if rel.startswith('http') else urljoin(origin + '/', rel.lstrip('/'))
        if scope.in_scope_host(url):
            items.append({"url": url, "param": "", "source": "js/html"})
    for au in sorted(found_abs):
        if scope.in_scope_host(au):
            items.append({"url": au, "param": "", "source": "absolute"})
        else:
            oos.add(urlparse(au).netloc)
    for f in forms:
        if scope.in_scope_host(f["action"]):
            for p in (f["params"] or [""]):
                items.append({"url": f["action"], "param": p, "source": "form", "method": "POST"})

    seen, uniq = set(), []
    for it in items:
        k = (it["url"], it.get("param", ""))
        if k not in seen:
            seen.add(k); uniq.append(it)
    if interesting_only:
        testable = [it for it in uniq if _testable(it)]
        log(f"recon: {len(uniq)} route(s) total -> {len(testable)} testable endpoint(s) "
            f"({len(uniq) - len(testable)} marketing/content pages filtered out)")
        uniq = testable
    # secrets are findings in themselves — always kept as info-leak items
    for s in secrets:
        uniq.append({"url": s["url"], "param": "", "vuln_class": "info-leak", "source": "secret",
                     "note": f"{s['type']} exposed in client-side JS",
                     "evidence": f"{s['type']} = {s['redacted']} (in {s['url']})"})
    return uniq, sorted(oos)


def classify(item):
    """Cheap heuristic -> likely vuln class (no LLM). Param-name signals win first."""
    url = item.get("url", "").lower()
    p = (item.get("param", "") or "").lower()
    PARAM = {
        "open-redirect": {"url", "uri", "next", "redirect", "return", "returnurl", "return_url",
                          "callback", "goto", "dest", "destination", "continue", "u", "link", "target"},
        "lfi": {"file", "path", "page", "template", "include", "doc", "document", "filename", "filepath", "load"},
        "ssrf": {"image", "imageurl", "image_url", "fetch", "webhook", "proxy", "feed", "host", "port", "ip", "endpoint"},
        "idor": {"id", "uid", "user", "userid", "user_id", "account", "accountid", "order",
                 "orderid", "invoice", "docid", "pid", "oid", "ref"},
        "sqli": {"q", "query", "search", "keyword", "s", "term", "filter", "sort"},
    }
    for cls, names in PARAM.items():
        if p in names:
            return cls
    rules = [
        (("/graphql",), "graphql"),
        (("/chat", "/ai", "/llm", "completion", "/assistant", "/agent", "prompt", "/copilot"), "llm-ai"),
        (("redirect", "returnurl", "callback", "goto", "/go"), "open-redirect"),
        (("/upload", "filename", "filepath", "/download", "/file"), "lfi"),
        (("/account", "/users", "/user/", "userid", "/profile", "/order", "/invoice", "/report", "/export"), "idor"),
        (("/search", "/query", "keyword"), "sqli"),
        (("/login", "/signin", "/register", "/auth", "/oauth", "/token", "/session"), "auth-bypass"),
        (("/proxy", "/fetch", "webhook"), "ssrf"),
    ]
    for keys, cls in rules:
        if any(k in url for k in keys):
            return cls
    return "idor" if p else "info-leak"


def classify_all(item, max_classes=None):
    """Work units for an endpoint. Deep mode is one thinking hunt per URL — not a
    vuln-class matrix. A preset secret finding stays single-class. The keyword
    matrix below is only used when HUNT_DEEP is off (tests / explicit class mode)."""
    if item.get("source") == "secret" and item.get("vuln_class"):
        return [item["vuln_class"]]
    if os.environ.get("HUNT_DEEP", "1") == "1":
        return ["deep"]
    if max_classes is None:
        max_classes = int(os.environ.get("HUNT_MAX_CLASSES", "10"))
    url = item.get("url", "").lower()
    p = (item.get("param", "") or "").lower()
    classes = [classify(item)]
    extras = ["idor", "auth-bypass", "info-leak"]   # universal access / exposure
    # context-SPECIALISED classes FIRST (before the generic injection matrix) so they survive the cap
    if any(k in url for k in ("/login", "/signin", "/register", "/auth", "/oauth", "/token",
                              "/session", "/sso", "/saml", "/mfa", "/2fa", "/otp", "/password", "/reset")):
        extras += ["jwt", "oauth", "csrf", "mfa", "saml"]
    if any(k in url for k in ("/chat", "/ai", "/llm", "/assistant", "/agent", "/copilot", "prompt")):
        extras += ["llm-ai"]
    if "/graphql" in url or "/gql" in url:
        extras += ["graphql"]
    if any(k in url for k in ("/upload", "/file", "/download", "/import", "/attachment", "/avatar", "/media")):
        extras += ["file-upload", "xxe"]
    if any(k in url for k in ("/webhook", "/callback", "/fetch", "/proxy", "/integration", "/notify")):
        extras += ["webhook"]
    extras += ["ssrf", "open-redirect", "cors"]     # more universal
    if (bool(p) or "?" in url or any(k in url for k in ("/api", "/rest", "/v1", "/v2", "/v3", "/graphql",
            "/gql", "/rpc", "/ajax", "/json", "/search", "/query", ".php", ".asp", ".jsp", ".do"))):
        extras += ["sqli", "nosqli", "xss", "ssti", "lfi", "cmdi", "xxe"]   # full injection matrix on any input
    for e in extras:
        if e not in classes:
            classes.append(e)
    return classes[:max_classes]


# tracking / cache params with no attack value — dropped from the surface
PARAM_NOISE = {"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "gclid",
               "fbclid", "msclkid", "mc_cid", "mc_eid", "ref", "trk", "v", "ver", "_", "ts",
               "cache", "cb", "rnd", "version"}


def classes_for_param(name, url=""):
    """Deterministic per-parameter attack categorization (name-driven). Returns ranked classes."""
    n = (name or "").lower()
    cls = []
    def add(*cs):
        for c in cs:
            if c not in cls:
                cls.append(c)
    if n in ("url", "uri", "next", "dest", "destination", "u", "link", "target", "return", "continue") \
            or any(k in n for k in ("redirect", "returnurl", "return_to", "callback", "goto", "forward")):
        add("open-redirect", "ssrf")
    if any(k in n for k in ("image", "fetch", "webhook", "proxy", "feed", "remote", "load_url")):
        add("ssrf")
    if (any(k in n for k in ("file", "path", "template", "include", "document", "folder", "dir"))
            and not n.endswith("id")):
        add("lfi")
    if n in ("id", "uid", "pid", "oid", "gid") or n.endswith("_id") or n.endswith("id") \
            or any(k in n for k in ("user", "account", "order", "invoice", "node", "post", "item", "doc", "page", "cat", "tag", "profile")):
        add("idor", "sqli")
    if n in ("q", "s", "query", "search", "keyword", "filter", "term", "sort", "name", "email", "cat", "tag", "lang"):
        add("sqli", "xss")
    if any(k in n for k in ("auth", "token", "session", "login", "sso", "saml", "oauth")):
        add("auth-bypass")
    if not cls:
        add("sqli", "xss", "idor")     # any reflected/used param is a generic injection/IDOR surface
    return cls[:3]


def _gau_urls(scope, log):
    """Passive: gau historical parameterized URLs (in-scope). url -> source.
    Bounded: per-apex timeout + a total time budget + progress logs — a silent
    multi-apex hang looks exactly like a stuck hunt to the watchdog."""
    import subprocess, time
    from urllib.parse import urlparse
    if not which("gau"):
        log("params: gau not installed — skipping historical param discovery")
        return {}
    apexes = set()
    for s in scope.seeds:
        h = urlparse(s if "://" in s else "//" + s).hostname
        if h:
            apexes.add(".".join(h.split(".")[-2:]))
    urls = {}
    apexes = sorted(apexes)
    t0 = time.time()
    for i, apex in enumerate(apexes, 1):
        if time.time() - t0 > 360:                       # total gau budget: 6 min
            log(f"params: gau budget exhausted after {i-1}/{len(apexes)} apex(es) — continuing with what we have")
            break
        try:
            out = subprocess.run(["gau", apex], capture_output=True, text=True, timeout=90, env=_TOOL_ENV).stdout
        except Exception:
            out = ""
        for u in out.splitlines():
            u = u.strip()
            if u and "?" in u and scope.in_scope_host(u):
                urls.setdefault(u, "gau-historical")
        if i % 5 == 0 or i == len(apexes):
            log(f"params: gau {i}/{len(apexes)} apex(es), {len(urls)} URL(s) so far ({int(time.time()-t0)}s)")
    log(f"params: gau -> {len(urls)} in-scope parameterized historical URL(s)"
        + ("" if urls else " (0 — gau likely rate-limited/transient this run; katana below is independent)"))
    return urls


def _katana_urls(scope, log, depth=2, timeout=45, max_seeds=30, budget_s=480):
    """Active live crawl (katana, GET-only) -> in-scope URLs. Independent of gau's flakiness.
    Bounded: crawls a ROTATING window of at most max_seeds seeds per pass, per-seed timeout,
    a total time budget, and progress logs. Before this, a program with hundreds of seeds
    crawled silently for ~1h and the watchdog (correctly) read it as a stuck hunt."""
    import subprocess, time, hashlib
    if not which("katana"):
        log("params: katana not installed — skipping live crawl")
        return {}
    seeds = list(scope.seeds)
    if len(seeds) > max_seeds:
        # deterministic rotating window (~per 3h pass): full coverage across passes, bounded per pass
        off = int(hashlib.md5(str(int(time.time() // 10800)).encode()).hexdigest(), 16) % len(seeds)
        seeds = (seeds[off:] + seeds[:off])[:max_seeds]
        log(f"params: katana crawling a rotating window of {len(seeds)}/{len(scope.seeds)} seeds this pass")
    urls, crawled = {}, 0
    t0 = time.time()
    for i, seed in enumerate(seeds, 1):
        if time.time() - t0 > budget_s:
            log(f"params: katana budget exhausted after {i-1}/{len(seeds)} seed(s) — continuing with what we have")
            break
        try:
            out = subprocess.run(["katana", "-u", seed, "-silent", "-jc", "-d", str(depth),
                                  "-kf", "all", "-c", "10", "-timeout", "10", "-rl", "100"],
                                 capture_output=True, text=True, timeout=timeout, env=_TOOL_ENV).stdout
        except Exception:
            out = ""
        for u in out.splitlines():
            u = u.strip()
            if u and scope.in_scope_host(u):
                crawled += 1
                if "?" in u:
                    urls.setdefault(u, "katana-crawl")
        if i % 5 == 0 or i == len(seeds):
            log(f"params: katana {i}/{len(seeds)} seed(s), {len(urls)} parameterized so far ({int(time.time()-t0)}s)")
    log(f"params: katana live-crawl -> {crawled} in-scope URL(s), {len(urls)} parameterized")
    return urls


def _probe(url, timeout=12):
    """GET via the shared transport so probes honor target UA, auth, proxy, and impersonation."""
    try:
        import netget
        code, body, _headers = netget.get(
            url, method="GET", headers={"User-Agent": _ua()}, timeout=timeout,
            ident=os.environ.get("HUNT_RECON_IDENT") or None,
            slug=os.environ.get("HUNT_TARGET_SLUG") or None)
        return int(code or 0), body or ""
    except Exception:
        return 0, ""


def prune_inert_params(items, log=print, max_keep=None, probe_budget=None):
    """Drop param items whose ENDPOINT is dead (>=400) or whose PARAM is inert (no effect on the
    response beyond echoing itself). Deterministic: marker-normalized body-diff vs the no-param
    baseline — removing the marker first neutralizes the canonical/og:url reflection trap. Keeps
    only live, processable params. Scans until max_keep live pairs are retained, bounded separately by
    a hard request budget. (Active: ~1 request per unique endpoint + 1 per param.)"""
    if probe_budget is None:
        probe_budget = int(os.environ.get("HUNT_PARAM_PROBE_BUDGET", "240"))
    kept, dead, inert, base_cache, probes = [], 0, 0, {}, 0
    marker = "zq9k7xp"
    for it in items:
        if max_keep is not None and len(kept) >= max_keep:
            break
        base_path = it.get("url", "").split("?", 1)[0]
        param = it.get("param", "")
        if base_path not in base_cache:
            if probes >= probe_budget:
                break
            base_cache[base_path] = _probe(base_path)
            probes += 1
        bcode, bbody = base_cache[base_path]
        if bcode == 0 or bcode >= 400:
            dead += 1
            continue                                   # dead endpoint
        if probes >= probe_budget:
            break
        tcode, tbody = _probe(f"{base_path}?{param}={marker}")
        probes += 1
        if tcode == 0 or tcode >= 400:
            dead += 1
            continue
        norm = tbody.replace(marker, "")               # strip the param's own echo (canonical/og:url)
        if abs(len(norm) - len(bbody)) <= 8 and norm[:6000] == bbody[:6000]:
            inert += 1
            continue                                   # param ignored — no effect on response
        kept.append(it)
    if dead or inert:
        log(f"params: inertness-prune dropped {dead} dead-endpoint + {inert} inert param(s) "
            f"-> {len(kept)} live/processable remain")
    if probes >= probe_budget and (max_keep is None or len(kept) < max_keep):
        log(f"params: inertness-prune probe budget exhausted ({probes}/{probe_budget}) "
            f"with {len(kept)} live/processable retained")
    return kept


OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/v1/openapi.json",
                 "/api-docs", "/swagger/v1/swagger.json", "/api/v1/openapi.json"]


def classes_for_openapi(path, method, op, secured):
    """Categorize an OpenAPI operation into attack classes (name + shape driven)."""
    pl = path.lower()
    cls = []
    def add(*cs):
        for c in cs:
            if c not in cls:
                cls.append(c)
    if "{" in path:                       # path parameter -> object reference (IDOR/BOLA)
        add("idor")
    if any(k in pl for k in ("/admin", "permission", "role", "/users", "/orgs", "deactivate",
                             "reactivate", "/members")):
        add("auth-bypass")                # broken access control / privilege escalation
    if any(k in pl for k in ("sso", "saml")):
        add("saml")
    if any(k in pl for k in ("oauth", "keycloak", "/auth", "/login", "token")):
        add("auth-bypass")
    has_param = any(pr.get("in") in ("query", "path") for pr in op.get("parameters", []))
    if has_param or method in ("post", "put", "patch"):
        add("sqli")
    if not cls:
        add("info-leak")
    return cls[:3]


def auth_enforcement_sweep(spec, base, log=print, junk="zzz-pentest-nonexistent-00000", allow_intrusive=False):
    """Probe each DECLARED-secured op unauthenticated; flag any that don't reject (the #1 API risk:
    declared != enforced). SAFE: junk path-ids (destructive ops hit non-existent resources), empty
    bodies (writes hit validation, not execution). 2xx/422 unauth = NOT enforced. Returns broken items."""
    import urllib.request
    import urllib.error
    import time
    glob = "security" in spec
    allowed = ("get", "head", "options") if not allow_intrusive else ("get", "post", "put", "patch", "delete")
    broken, n = [], 0
    for path, methods in spec.get("paths", {}).items():
        for m, op in methods.items():
            if m not in allowed:
                continue
            if not (("security" in op and op["security"] != []) or ("security" not in op and glob)):
                continue
            url = base + path
            for pp in op.get("parameters", []):
                if pp.get("in") == "path":
                    url = url.replace("{%s}" % pp["name"], junk)
            url = url.replace("{", "").replace("}", "")
            q = [f"{pp['name']}={junk}" for pp in op.get("parameters", [])
                 if pp.get("in") == "query" and pp.get("required")]
            if q:
                url += ("&" if "?" in url else "?") + "&".join(q)
            data = b"{}" if m in ("post", "put", "patch") else None
            req = urllib.request.Request(url, data=data, method=m.upper(),
                                         headers={"Accept": "application/json", "Content-Type": "application/json"})
            try:
                code = urllib.request.urlopen(req, timeout=10).status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception:
                code = 0
            n += 1
            if code in (200, 201, 202, 204, 422):     # reached the handler/validation unauth = NOT enforced
                broken.append({"url": url, "param": "", "vuln_class": "auth-bypass", "source": "auth-sweep",
                               "note": f"{m.upper()} {path} -> {code} UNAUTH (declared-secured, NOT enforced)"})
            time.sleep(0.03)
    if broken:
        log(f"auth-sweep: ⚠ {len(broken)}/{n} declared-secured op(s) NOT auth-enforced (BROKEN function-level auth)")
    else:
        log(f"auth-sweep: {n}/{n} declared-secured op(s) correctly enforce auth (401/403) — verified")
    return broken


WELLKNOWN = ["/__/firebase/init.json", "/.well-known/oauth-authorization-server",
             "/.well-known/oauth-protected-resource", "/.well-known/openid-configuration",
             "/.well-known/security.txt", "/security.txt", "/robots.txt"]


def platform_recon(scope, log=print):
    """Probe platform/.well-known config endpoints — cheap, high-signal: Firebase config disclosure,
    OAuth/OIDC discovery (reveals authorize/token/register), robots disallows. Returns surface items."""
    import json as _json
    from urllib.parse import urlparse
    items, seen = [], set()
    for seed in scope.seeds:
        u = urlparse(seed if "://" in seed else "https://" + seed)
        base = f"{u.scheme or 'https'}://{u.hostname}"
        if base in seen:
            continue
        seen.add(base)
        for wk in WELLKNOWN:
            code, body = _probe(base + wk)
            if code != 200:
                continue
            b = body.lstrip()
            if "firebase/init" in wk and b.startswith("{"):
                try:
                    cfg = _json.loads(body)
                    log(f"platform: {base}{wk} -> Firebase config (projectId={cfg.get('projectId','')}, "
                        f"bucket={cfg.get('storageBucket','')})")
                    items.append({"url": base + wk, "param": "", "vuln_class": "info-leak", "source": "platform",
                                  "note": f"Firebase config disclosed (projectId={cfg.get('projectId','')})"})
                except Exception:
                    pass
            elif ("oauth" in wk or "openid" in wk) and b.startswith("{"):
                try:
                    meta = _json.loads(body)
                    log(f"platform: {base}{wk} -> OAuth/OIDC discovery (issuer={meta.get('issuer','')})")
                    items.append({"url": base + wk, "param": "", "vuln_class": "info-leak", "source": "platform",
                                  "note": "OAuth/OIDC discovery exposed"})
                    for k in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
                        if meta.get(k):
                            items.append({"url": meta[k], "param": "", "vuln_class": "oauth",
                                          "source": "platform", "note": f"OAuth {k}"})
                except Exception:
                    pass
            elif "robots" in wk:
                raw = [ln.split(":", 1)[1].strip() for ln in body.splitlines()
                       if ln.lower().startswith("disallow:")]
                # keep only CONCRETE paths: no glob/query patterns (/*manifest, /*?*builder.preview*,
                # */search?*), no static assets. A robots glob is a pattern, not a curl-able URL.
                cand = []
                for d in raw:
                    if not d or not d.startswith("/") or d == "/":
                        continue
                    if any(c in d for c in "*$?") or is_static_asset(d):
                        continue
                    if d not in cand:
                        cand.append(d)
                # Soft-404 baseline: SPA / CDN catch-all sites return 200 + the app-shell HTML for EVERY
                # path (with path-dependent length, so size alone is useless), so "exists" can't mean "not
                # 404". Probe a random non-existent path to learn the catch-all; then DROP any disallow that
                # returns the same status AND is itself HTML shell. A genuine leak (/.env, /.git/config, a
                # JSON API) is NOT HTML, so it survives; a real gated path (different status) also survives.
                import random as _rnd
                import string as _str
                _is_html = lambda b: bool(re.search(r'<!doctype html|<html[\s>]', (b or "")[:400], re.I))
                bcode, bbody = _probe(base + "/zz-" + "".join(_rnd.choices(_str.ascii_lowercase + _str.digits, k=14)))
                base_shell = _is_html(bbody)
                live = []
                for d in cand[:12]:
                    code, cbody = _probe(base + d)
                    if not code or code in (404, 410):
                        continue
                    if code == bcode and base_shell and _is_html(cbody):
                        continue                         # just the catch-all app shell — not a real resource
                    live.append((d, code))
                if raw:
                    log(f"platform: {base}/robots.txt -> {len(raw)} disallow(s), {len(cand)} concrete, "
                        f"{len(live)} live: {', '.join(d for d, _ in live[:6]) or '(none)'}")
                for d, code in live:
                    items.append({"url": base + d, "param": "", "vuln_class": "info-leak",
                                  "source": "robots-disallow", "note": f"robots-disallowed path (live, {code})"})
            elif "security.txt" in wk:
                log(f"platform: {base}{wk} -> security.txt present")
    return items


def openapi_recon(scope, log=print):
    """If the target exposes an OpenAPI schema, parse it into categorized (path,method,class) work
    units — the ideal deterministic recon for an API host. Returns already-expanded surface items."""
    import json as _json
    items = []
    for seed in scope.seeds:
        host = seed.rstrip("/")
        if "://" not in host:
            host = "https://" + host
        for op_path in OPENAPI_PATHS:
            code, body = _probe(host + op_path)
            if code != 200 or not body.lstrip().startswith("{"):
                continue
            try:
                spec = _json.loads(body)
            except Exception:
                continue
            paths = spec.get("paths")
            if not paths:
                continue
            glob_sec = "security" in spec
            title = spec.get("info", {}).get("title", "API")
            noauth = 0
            for p, methods in paths.items():
                for m, opn in methods.items():
                    if m not in ("get", "post", "put", "patch", "delete"):
                        continue
                    secured = ("security" in opn and opn["security"] != []) or \
                              ("security" not in opn and glob_sec)
                    if not secured:
                        noauth += 1
                    for cls in classes_for_openapi(p, m, opn, secured):
                        items.append({"url": f"{host}{p}", "param": "", "method": m.upper(),
                                      "vuln_class": cls, "source": "openapi",
                                      "note": f"{m.upper()} {p} [{'AUTH' if secured else 'NO-AUTH'}]"})
            log(f"openapi: {host}{op_path} -> '{title}', {len(paths)} path(s) "
                f"({noauth} no-auth op(s)) -> {len(items)} categorized unit(s)")
            items += auth_enforcement_sweep(spec, host, log)   # verify declared-secured ops actually enforce
            break
    return items


def gather_params(scope, log=print, max_items=80):
    """Deterministic parameter discovery from TWO independent sources — gau (passive historical)
    and katana (active live crawl) — merged, scope/noise-filtered into (endpoint,param) pairs,
    then inertness-pruned so only live/processable params reach the map."""
    from urllib.parse import urlparse, parse_qs
    src = {}
    for u, s in _gau_urls(scope, log).items():
        src.setdefault(u, s)
    for u, s in _katana_urls(scope, log).items():
        src.setdefault(u, s)
    items, seen = [], set()
    for u in sorted(src):
        base = u.split("?", 1)[0]
        if base.count("://") != 1 or re.search(r'https?:/', urlparse(u).path or ""):
            continue  # skip malformed entries (double-scheme, etc.)
        if is_static_asset(base) or "*" in u:
            continue  # a static file (img/css/js/font) has no injectable param; a glob isn't a URL
        for p in parse_qs(urlparse(u).query):
            pl = p.lower()
            if pl in PARAM_NOISE or pl.startswith("utm_"):
                continue
            key = (base, pl)
            if key in seen:
                continue
            seen.add(key)
            items.append({"url": f"{base}?{p}=FUZZ", "param": p, "method": "GET", "source": src[u]})
    log(f"params: {len(items)} unique (endpoint,param) pair(s) from gau+katana after noise filter")
    return prune_inert_params(items, log, max_keep=max_items)


# ---------------- deep / authenticated recon (the authed API surface curl recon misses) --------------
_GQL_INTROSPECT = ('{"query":"query IntrospectionQuery{__schema{queryType{name} mutationType{name} '
                   'types{name kind fields{name}}}}"}')
_GQL_PATHS = ("/graphql", "/api/graphql", "/gql", "/v1/graphql", "/query", "/graphql/v1", "/api/gql")


def graphql_recon(scope, slug=None, ident=None, log=print, timeout=20, max_probes=12):
    """Find in-scope GraphQL endpoints and introspect them (AUTHENTICATED if a session exists). Open
    introspection is itself report-worthy AND yields per-operation surface (query/mutation names ->
    authz/IDOR targets). A reachable-but-closed endpoint is still graphql surface. Returns surface
    items [{url, param?, vuln_class, source, priority, note}]. Never raises into recon."""
    try:
        import netget
    except Exception:  # noqa: BLE001
        return []
    cand = []
    for s in scope.seeds:
        u = urlparse(s)
        base = f"{u.scheme or 'https'}://{u.hostname}"
        first = (u.hostname or "").split(".")[0]
        if first in ("gql", "graphql"):
            cand += [base, base + "/graphql"]
        for p in _GQL_PATHS:
            cand.append(base + p)
    cand = [u for u in dict.fromkeys(cand) if scope.in_scope_host(u)][:max_probes]
    out = []
    for u in cand:
        try:
            code, text, _h = netget.get(u, method="POST", data=_GQL_INTROSPECT,
                                        headers={"Content-Type": "application/json"},
                                        ident=ident, slug=slug, timeout=timeout)
        except Exception:  # noqa: BLE001
            continue
        if not text:
            continue
        gql_shaped = ('"__schema"' in text or '"errors"' in text or '"data"' in text
                      or "Must provide query" in text or "GraphQL" in text)
        if not gql_shaped:
            continue
        schema = None
        try:
            import json as _json
            schema = ((_json.loads(text).get("data") or {}).get("__schema"))
        except Exception:  # noqa: BLE001
            schema = None
        if schema:
            out.append({"url": u, "vuln_class": "graphql", "source": "graphql-introspect",
                        "priority": 72, "note": "introspection OPEN"})
            qn = (schema.get("queryType") or {}).get("name")
            mn = (schema.get("mutationType") or {}).get("name")
            ops = [f.get("name") for t in (schema.get("types") or [])
                   if t.get("name") in (qn, mn) for f in (t.get("fields") or []) if f.get("name")]
            for op in ops[:60]:
                out.append({"url": u, "param": op, "vuln_class": "idor",
                            "source": "graphql-op", "priority": 66, "note": f"gql op {op}"})
            log(f"graphql: introspection OPEN at {u} -> {len(ops)} operation(s) mapped")
            break
        else:                                   # live graphql, introspection closed -> still surface
            out.append({"url": u, "vuln_class": "graphql", "source": "graphql-endpoint",
                        "priority": 52, "note": "live graphql (introspection closed)"})
            log(f"graphql: live endpoint (introspection closed) at {u}")
            break
    if not out:
        log("graphql: no reachable GraphQL endpoint on probed paths")
    return out


def _browser_lock_path(base):
    d = os.path.join(os.path.expanduser(base or "~/.bughunter-engagements"), "_sessions")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return os.path.join(d, "_browser.lock")


def browser_recon(scope, base=None, slug=None, ident=None, log=print, max_seeds=3, wait=5):
    """Headless-browser capture of the authed SPA's REAL API (XHR/fetch/GraphQL) — the single biggest
    discovery win, and the surface curl recon cannot see (a thick client makes its data calls at
    runtime). Carries identity A (the operator/provisioned session). Resource-safe for a small box: at
    most ONE Chromium box-wide (non-blocking global lock -> skip if busy), capped seeds + short waits.
    Returns endpoint items [{url, method, source}]. Never raises into recon."""
    if os.environ.get("HUNT_BROWSER_RECON", "1") != "1":
        return []
    try:
        import browser as B
        import fcntl
    except Exception as e:  # noqa: BLE001
        log(f"browser-recon: unavailable ({type(e).__name__}: {e})")
        return []
    fd = os.open(_browser_lock_path(base), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("browser-recon: another capture is running box-wide — skipping (2-core safe)")
            return []
        seeds = [s for s in scope.seeds if scope.in_scope_host(s)][:max_seeds]
        scope_hosts = sorted({urlparse(s).hostname for s in scope.seeds if urlparse(s).hostname})
        out, seen = [], set()
        for seed in seeds:
            try:
                reqs = B.capture(seed, slug=slug, ident=ident, scope_hosts=scope_hosts, wait=wait, pages=2)
            except Exception as e:  # noqa: BLE001
                log(f"browser-recon: {seed} failed ({type(e).__name__}: {str(e)[:90]})")
                continue
            for r in (reqs or []):
                u = (r.get("url") or "").split("#")[0]
                if not u or u in seen or not scope.in_scope_host(u):
                    continue
                rtype = r.get("type", "")
                if rtype in ("form", "button") or _browser_api_request(r):
                    seen.add(u)
                    item = {"url": u, "method": r.get("method", "GET"), "source": "browser"}
                    if rtype in ("form", "button"):
                        item["source"] = rtype
                        item["function"] = r.get("function", "")
                    if r.get("inputs"):
                        item["inputs"] = r["inputs"]
                    out.append(item)
                elif is_concrete_target(u) and _browser_api_request(r):
                    seen.add(u)
                    out.append({"url": u, "method": r.get("method", "GET"), "source": "browser"})
        log(f"browser-recon: {len(out)} in-scope API endpoint(s) from {len(seeds)} seed(s)"
            + (f" (authenticated as {ident})" if ident else " (unauthenticated)"))
        return out
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:  # noqa: BLE001
            pass
        os.close(fd)


def toolcheck():
    """Print which recon tools are available and which are missing."""
    tools = {
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "gf": "go install github.com/tomnomnom/gf@latest",
        "interactsh-client": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "curl": "apt install curl",
        "jq": "apt install jq",
    }
    gobin = os.path.expanduser("~/go/bin")
    ok, missing = [], []
    for name, install in tools.items():
        found = which(name) or (os.path.isfile(os.path.join(gobin, name)) and os.path.join(gobin, name))
        if found:
            ok.append(f"  [OK] {name:22s} {found}")
        else:
            missing.append(f"  [--] {name:22s} install: {install}")
    print("Recon tool check:")
    for line in ok:
        print(line)
    for line in missing:
        print(line)
    print(f"\n{len(ok)} available, {len(missing)} missing")
    if missing:
        print(f"\nHint: export PATH=$PATH:{gobin}")
    return len(missing) == 0


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from scope import Scope
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        sys.exit(0 if toolcheck() else 1)
    if len(sys.argv) > 1:                      # live test: python3 recon.py https://target/  host
        seeds = [sys.argv[1]]
        host = sys.argv[2] if len(sys.argv) > 2 else urlparse(sys.argv[1]).hostname
        sc = Scope(in_scope=[host, "*." + host], seeds=seeds, name="adhoc")
        items, oos = spa_recon(sc)
        print(f"\n{len(items)} in-scope surface item(s):")
        for it in items:
            print(f"  [{classify(it):13s}] {it['url']}  {('· ' + it['param']) if it.get('param') else ''}")
        print(f"\nout-of-scope hosts seen (NOT tested): {', '.join(oos[:15])}")
    else:                                      # offline regex self-test
        rel, ab = set(), set()
        _mine('a "/api/completion" b fetch("/api/v1/users") <a href="https://api.acme.com/x">'
              ' "/graphql" "https://www.googleapis.com/y"', rel, ab)
        assert "/api/completion" in rel and "/api/v1/users" in rel and "/graphql" in rel, rel
        assert "https://api.acme.com/x" in ab, ab
        assert not any("googleapis" in a for a in ab), "noise not filtered"
        assert classify({"url": "/api/completion"}) == "llm-ai"
        assert classify({"url": "/api/account", "param": "id"}) == "idor"
        assert classify({"url": "/go", "param": "url"}) == "open-redirect"
        assert classify({"url": "/x", "param": "file"}) == "lfi"
        # junk-target filter: globs + static assets are not concrete targets
        assert is_concrete_target("https://api.x.com/account")
        assert is_concrete_target("https://api.x.com/users?id=FUZZ")      # FUZZ marker is fine
        assert not is_concrete_target("https://api.x.com/api/*")          # robots/scope glob
        assert not is_concrete_target("https://x.com/*?*builder.preview*")
        assert not is_concrete_target("https://x.com/a/b/6697_h.gif?cc=FUZZ")  # static asset
        assert not is_concrete_target("https://x.com/app.js")
        assert not is_concrete_target("https://x.com/cdn-cgi/challenge-platform/h/b/orchestrate?ray=1")
        assert is_static_asset("https://x.com/main.css") and not is_static_asset("https://x.com/api/css-theme")
        # Browser surface is API-only: no navigations, marketing, static, or edge challenge traffic.
        assert _browser_api_request({"url": "https://x.com/api/users", "type": "xhr"})
        assert not _browser_api_request({"url": "https://x.com/api/users", "type": "document"})
        assert not _browser_api_request({"url": "https://x.com/cdn-cgi/challenge-platform/x?ray=1", "type": "fetch"})
        assert not _browser_api_request({"url": "https://x.com/help/account?q=x", "type": "xhr"})

        # Relative routes stay on the seed that disclosed them rather than moving to the first seed.
        class _Scope:
            seeds = ["https://one.test", "https://two.test"]
            @staticmethod
            def in_scope_host(u):
                return (urlparse(u).hostname or "") in ("one.test", "two.test")
        old_get = _get
        try:
            globals()["_get"] = lambda u, timeout=20: (
                ('"/api/one"' if "one.test" in u else '"/api/two"') if not u.endswith(("robots.txt", "sitemap.xml")) else "",
                u, {})
            bound, _ = spa_recon(_Scope(), max_js=0, log=lambda _m: None)
        finally:
            globals()["_get"] = old_get
        bound_urls = {it["url"] for it in bound}
        assert "https://one.test/api/one" in bound_urls, bound_urls
        assert "https://two.test/api/two" in bound_urls, bound_urls
        assert "https://one.test/api/two" not in bound_urls, bound_urls

        # Probes use the shared transport and propagate target-specific UA/auth context.
        import types
        calls = []
        old_netget = sys.modules.get("netget")
        old_env = {k: os.environ.get(k) for k in ("HUNT_USER_AGENT", "HUNT_RECON_IDENT", "HUNT_TARGET_SLUG")}
        try:
            sys.modules["netget"] = types.SimpleNamespace(
                get=lambda url, **kw: (calls.append((url, kw)) or (200, "ok", {})))
            os.environ["HUNT_USER_AGENT"] = "Recon-Test-UA"
            os.environ["HUNT_RECON_IDENT"] = "A"
            os.environ["HUNT_TARGET_SLUG"] = "probe-test"
            assert _probe("https://x.test/api") == (200, "ok")
        finally:
            if old_netget is None:
                sys.modules.pop("netget", None)
            else:
                sys.modules["netget"] = old_netget
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        assert calls[0][1]["headers"]["User-Agent"] == "Recon-Test-UA", calls
        assert calls[0][1]["ident"] == "A" and calls[0][1]["slug"] == "probe-test", calls

        # Impersonated recon follows only scoped redirects and returns the final body/URL.
        old_netget = sys.modules.get("netget")
        redirect_calls = []
        try:
            def _redirects(u, **kw):
                redirect_calls.append(u)
                if u == "https://x.test/":
                    return 302, "", {"location": "/login"}
                return 200, "login-body", {"server": "test"}
            sys.modules["netget"] = types.SimpleNamespace(get=_redirects)
            body, final, hdrs = _get_impersonate("https://x.test/")
            assert (body, final, hdrs.get("server")) == ("login-body", "https://x.test/login", "test")
            assert redirect_calls == ["https://x.test/", "https://x.test/login"], redirect_calls
            sys.modules["netget"] = types.SimpleNamespace(
                get=lambda u, **kw: (0, "", {"_error": "scope violation"}))
            assert _get_impersonate("https://x.test/") == ("", "https://x.test/", {})
        finally:
            if old_netget is None:
                sys.modules.pop("netget", None)
            else:
                sys.modules["netget"] = old_netget

        # Pruning scans past dead early candidates until the live-retention cap or hard probe budget.
        old_probe = _probe
        try:
            globals()["_probe"] = lambda u, timeout=12: ((404, "") if "/dead" in u else
                                                          (200, "changed") if "?" in u else (200, "base"))
            candidates = [{"url": f"https://x.test/dead{i}?q=FUZZ", "param": "q"} for i in range(3)]
            candidates += [{"url": f"https://x.test/live{i}?q=FUZZ", "param": "q"} for i in range(3)]
            retained = prune_inert_params(candidates, log=lambda _m: None, max_keep=2, probe_budget=10)
        finally:
            globals()["_probe"] = old_probe
        assert len(retained) == 2 and all("/live" in it["url"] for it in retained), retained
        print("recon.py self-test: PASS")
