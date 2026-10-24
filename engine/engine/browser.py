#!/usr/bin/env python3
"""
browser.py — headless-browser recon: render a page (optionally authenticated) and capture the REAL
API surface (XHR / fetch / GraphQL / document requests) that curl-based recon misses on SPAs. This is
the single biggest discovery win — a thick-client SPA makes its data calls at runtime, not in the HTML.

Read-only by design: it navigates and waits for network-idle; it does NOT submit forms or click
destructive actions. Carries the program UA + optional authenticated session (ident A/B) + scope filter.

CLI:
  python3 browser.py capture --url https://app.x.com --slug x [--as A] [--scope app.x.com] [--wait 6]
"""
import argparse
import json
import os
import sys
from urllib.parse import urlparse

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

SKIP_TYPES = {"image", "font", "stylesheet", "media"}


def capture(url, slug=None, ident=None, scope_hosts=None, wait=6, timeout=25000, max_req=500, pages=5):
    """Render url and return captured requests [{method,url,type}] (XHR/fetch/doc/script/other), scope-filtered.
    `pages`>0 adds a BOUNDED, read-only deepening pass: scroll (lazy-loaded XHR) + visit up to `pages` more
    same-/in-scope in-app links (GET navigations only, never logout/delete/pay), under a hard time budget —
    reaches behind-nav API without turning into a slow crawl."""
    from playwright.sync_api import sync_playwright
    import authn
    reqs, seen = [], set()
    ua = os.environ.get("HUNT_USER_AGENT")
    sess_headers = {}
    if ident:
        af = os.environ.get("HUNT_AUTH_FILE")
        sess_headers = authn.headers_for(ident, slug_or_path=(af or slug))
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(user_agent=ua or None,
                            extra_http_headers={k: v for k, v in sess_headers.items() if k.lower() != "cookie"})
        if sess_headers.get("Cookie"):
            host = urlparse(url).hostname
            cookies = []
            for pair in sess_headers["Cookie"].split(";"):
                if "=" in pair:
                    n, v = pair.strip().split("=", 1)
                    cookies.append({"name": n, "value": v, "domain": host, "path": "/"})
            try:
                ctx.add_cookies(cookies)
            except Exception:  # noqa: BLE001
                pass
        pg = ctx.new_page()

        def on_req(r):
            try:
                if len(reqs) >= max_req or r.resource_type in SKIP_TYPES:
                    return
                base_url = r.url.split("?")[0]
                try:
                    from urllib.parse import urlparse, parse_qs
                    params = tuple(sorted(parse_qs(urlparse(r.url).query).keys()))
                except Exception:
                    params = ()
                key = (r.method, base_url, params)
                if key in seen:
                    return
                seen.add(key)
                reqs.append({"method": r.method, "url": r.url, "type": r.resource_type})
            except Exception:  # noqa: BLE001
                pass
        pg.on("request", on_req)
        try:
            pg.goto(url, timeout=timeout, wait_until="domcontentloaded")
            pg.wait_for_timeout(int(wait * 1000))
            if pages > 0:                                   # bounded, read-only deepening (hard budget)
                import time as _t
                host0 = urlparse(url).hostname or ""

                def _in_scope(hn):
                    if not hn:
                        return False
                    if scope_hosts:
                        return any(hn == s or hn.endswith("." + s) for s in scope_hosts)
                    return hn == host0
                try:
                    pg.evaluate("window.scrollTo(0, document.body.scrollHeight)")   # trigger lazy XHR
                    pg.wait_for_timeout(1200)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    hrefs = pg.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
                except Exception:  # noqa: BLE001
                    hrefs = []
                bad = ("logout", "signout", "sign-out", "/delete", "remove", "/pay", "purchase",
                       "checkout/complete", "unsubscribe", "cancel")
                nav, nseen = [], set()
                for h in hrefs:
                    hu = urlparse(h)
                    base = h.split("#")[0]
                    if (hu.scheme in ("http", "https") and _in_scope(hu.hostname)
                            and base not in nseen and base != url.split("#")[0]
                            and not any(x in h.lower() for x in bad)):
                        nseen.add(base)
                        nav.append(h)
                budget = _t.time() + 15                     # hard overall cap for the deepening pass
                for h in nav[:pages]:
                    if _t.time() > budget:
                        break
                    try:
                        pg.goto(h, timeout=timeout, wait_until="domcontentloaded")
                        pg.wait_for_timeout(1500)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as e:  # noqa: BLE001
            reqs.append({"_nav_error": str(e)[:160]})
        b.close()
    if scope_hosts:
        def ok(x):
            h = urlparse(x.get("url", "")).hostname or ""
            return any(h == s or h.endswith("." + s) for s in scope_hosts)
        reqs = [r for r in reqs if r.get("_nav_error") or ok(r)]
    return reqs


def screenshot(url, output_path, slug=None, ident=None, wait=4, timeout=15000):
    """Take a full-page screenshot for evidence collection."""
    from playwright.sync_api import sync_playwright
    import authn
    ua = os.environ.get("HUNT_USER_AGENT")
    sess_headers = {}
    if ident:
        af = os.environ.get("HUNT_AUTH_FILE")
        sess_headers = authn.headers_for(ident, slug_or_path=(af or slug))
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(user_agent=ua or None,
                            extra_http_headers={k: v for k, v in sess_headers.items() if k.lower() != "cookie"})
        if sess_headers.get("Cookie"):
            host = urlparse(url).hostname
            cookies = []
            for pair in sess_headers["Cookie"].split(";"):
                if "=" in pair:
                    n, v = pair.strip().split("=", 1)
                    cookies.append({"name": n, "value": v, "domain": host, "path": "/"})
            try:
                ctx.add_cookies(cookies)
            except Exception:
                pass
        page = ctx.new_page()
        try:
            page.goto(url, timeout=timeout, wait_until="networkidle")
        except Exception:
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
        page.wait_for_timeout(wait * 1000)
        page.screenshot(path=output_path, full_page=True)
        b.close()
    return output_path


def dom_xss_probe(url, params=None, timeout=10000):
    """Probe URL for DOM-based XSS by injecting canary into URL params and hash.
    Returns list of findings [{param, sink, evidence}]."""
    from playwright.sync_api import sync_playwright
    canary = "xRay0xDOM"
    findings = []
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context()
        page = ctx.new_page()
        alerts = []
        page.on("dialog", lambda d: (alerts.append(d.message), d.dismiss()))
        # Test hash-based injection
        for payload in [f"#{canary}", f"#<img/src=x onerror=alert('{canary}')>"]:
            test_url = url + payload
            try:
                page.goto(test_url, timeout=timeout, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                if alerts:
                    findings.append({"param": "hash", "sink": "alert", "evidence": alerts[-1], "url": test_url})
                    alerts.clear()
                html = page.content()
                if canary in html:
                    findings.append({"param": "hash", "sink": "innerHTML", "evidence": f"canary reflected in DOM", "url": test_url})
            except Exception:
                pass
        # Test query param injection
        for param in (params or ["q", "search", "query", "name", "redirect", "url", "next", "callback"]):
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={canary}"
            try:
                page.goto(test_url, timeout=timeout, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                if alerts:
                    findings.append({"param": param, "sink": "alert", "evidence": alerts[-1], "url": test_url})
                    alerts.clear()
            except Exception:
                pass
        b.close()
    return findings


def csrf_check(url, slug=None, ident=None, timeout=10000):
    """Check if a page has CSRF protection on its forms.
    Returns list of unprotected forms [{action, method, has_token}]."""
    from playwright.sync_api import sync_playwright
    import authn
    sess_headers = {}
    if ident:
        af = os.environ.get("HUNT_AUTH_FILE")
        sess_headers = authn.headers_for(ident, slug_or_path=(af or slug))
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(extra_http_headers={k: v for k, v in sess_headers.items() if k.lower() != "cookie"})
        if sess_headers.get("Cookie"):
            host = urlparse(url).hostname
            cookies = []
            for pair in sess_headers["Cookie"].split(";"):
                if "=" in pair:
                    n, v = pair.strip().split("=", 1)
                    cookies.append({"name": n, "value": v, "domain": host, "path": "/"})
            try:
                ctx.add_cookies(cookies)
            except Exception:
                pass
        page = ctx.new_page()
        try:
            page.goto(url, timeout=timeout, wait_until="networkidle")
        except Exception:
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
        forms = page.evaluate("""() => {
            return Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action,
                method: (f.method || 'GET').toUpperCase(),
                has_token: !!(f.querySelector('input[name*="csrf"]') ||
                             f.querySelector('input[name*="token"]') ||
                             f.querySelector('input[name*="_token"]') ||
                             f.querySelector('input[name*="authenticity"]'))
            }));
        }""")
        b.close()
    return [f for f in forms if f["method"] == "POST" and not f["has_token"]]


def _main(argv=None):
    ap = argparse.ArgumentParser(description="headless-browser API-surface capture")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("capture")
    pc.add_argument("--url", required=True); pc.add_argument("--slug")
    pc.add_argument("--as", dest="ident"); pc.add_argument("--scope", action="append", default=[])
    pc.add_argument("--wait", type=float, default=6)
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    if a.slug:
        os.environ.setdefault("HUNT_TARGET_SLUG", a.slug)
    reqs = capture(a.url, slug=a.slug, ident=a.ident, scope_hosts=a.scope or None, wait=a.wait)
    xhr = [r for r in reqs if r.get("type") in ("xhr", "fetch")]
    print(json.dumps(reqs, indent=2))
    print(f"\ncaptured {len(reqs)} request(s), {len(xhr)} XHR/fetch — feed the API ones to authz.py / the worklist.",
          file=sys.stderr)
    return 0


def _selftest():
    data_url = "data:text/html,<script>fetch('https://httpbin.org/get?probe=1')</script>"
    reqs = capture(data_url, wait=4)
    assert any("httpbin.org/get" in r.get("url", "") for r in reqs), reqs
    print("browser.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
