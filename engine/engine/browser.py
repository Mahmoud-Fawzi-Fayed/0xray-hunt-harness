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


def capture(url, slug=None, ident=None, scope_hosts=None, wait=6, timeout=25000, max_req=500, pages=5, scope=None):
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
        _install_scope_blocker(pg, scope)

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
                reqs.append({"method": r.method, "url": r.url, "source": r.resource_type})
            except Exception:  # noqa: BLE001
                pass
        pg.on("request", on_req)
        # Intercept fetch/XHR at JS level to capture calls triggered by interactions
        pg.add_init_script("""
        window.__xray_api = [];
        const _f = window.fetch;
        window.fetch = function(u, o) {
            var entry = {url:''+u, method:(o&&o.method||'GET').toUpperCase(), src:'fetch'};
            try { window.__xray_api.push(entry); } catch(e){}
            return _f.apply(this, arguments).then(function(r) {
                try { entry.status = r.status; } catch(e){}
                return r;
            });
        };
        const _xo = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(m, u) {
            try { window.__xray_api.push({url:''+u, method:m.toUpperCase(), src:'xhr'}); } catch(e){}
            return _xo.apply(this, arguments);
        };
        """)
        _form_seen = set()

        def _extract_page(page):
            """Extract forms, buttons, and intercepted API calls from current page."""
            try:
                forms = page.evaluate("""() => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action, method: (f.method||'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                        .map(i => i.name).filter(n => n).slice(0, 20)
                })).filter(f => f.action).slice(0, 50)""") or []
                for form in forms:
                    fk = (form["method"], form["action"])
                    if fk not in _form_seen:
                        _form_seen.add(fk)
                        reqs.append({"method": form["method"], "url": form["action"],
                                     "source": "form", "inputs": form.get("inputs", [])})
            except Exception:
                pass
            try:
                buttons = page.evaluate("""() => Array.from(document.querySelectorAll(
                    'button[formaction], input[type=submit][formaction], [role=button][data-url]'
                )).map(b => {
                    var form = b.closest('form');
                    return {
                        action: b.getAttribute('formaction') || b.getAttribute('data-url') || '',
                        method: (b.getAttribute('formmethod') || (form && form.method) || 'GET').toUpperCase(),
                        text: (b.innerText||b.value||'').trim().slice(0,60)
                    };
                }).filter(b => b.action).slice(0, 30)""") or []
                for btn in buttons:
                    bk = (btn.get("method", "GET"), btn.get("action", ""))
                    if bk not in _form_seen and btn.get("action"):
                        _form_seen.add(bk)
                        reqs.append({"method": btn.get("method", "GET"), "url": btn["action"],
                                     "source": "button", "function": btn.get("text", "")})
            except Exception:
                pass
            try:
                api_calls = page.evaluate("() => (window.__xray_api || []).slice(0, 200)") or []
                for call in api_calls:
                    u = call.get("url", "")
                    if u and u.startswith("http"):
                        reqs.append({"method": call.get("method", "GET"), "url": u,
                                     "source": call.get("src", "fetch")})
            except Exception:
                pass

        try:
            pg.goto(url, timeout=timeout, wait_until="domcontentloaded")
            pg.wait_for_timeout(int(wait * 1000))
            _extract_page(pg)
            if pages > 0:
                import time as _t
                host0 = urlparse(url).hostname or ""

                def _in_scope(hn):
                    if not hn:
                        return False
                    if scope_hosts:
                        return any(hn == s or hn.endswith("." + s) for s in scope_hosts)
                    return hn == host0
                try:
                    pg.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    pg.wait_for_timeout(1200)
                except Exception:
                    pass
                try:
                    hrefs = pg.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
                except Exception:
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
                budget = _t.time() + 15
                for h in nav[:pages]:
                    if _t.time() > budget:
                        break
                    try:
                        pg.goto(h, timeout=timeout, wait_until="domcontentloaded")
                        pg.wait_for_timeout(1500)
                        _extract_page(pg)
                    except Exception:
                        pass
        except Exception as e:
            reqs.append({"_nav_error": str(e)[:160]})
        b.close()
    if scope_hosts:
        def ok(x):
            h = urlparse(x.get("url", "")).hostname or ""
            return any(h == s or h.endswith("." + s) for s in scope_hosts)
        reqs = [r for r in reqs if r.get("_nav_error") or ok(r)]
    return reqs


def _install_scope_blocker(page, scope):
    """Install scope-enforcing route handler on a Playwright page. Fail-closed on error."""
    if not scope:
        return False
    _scope_obj = None
    try:
        import scope as _scope_mod
        if isinstance(scope, _scope_mod.Scope):
            _scope_obj = scope
        elif isinstance(scope, dict):
            _scope_obj = _scope_mod.Scope(scope.get("in_scope", []), scope.get("out_of_scope", []),
                                          path_restrictions=scope.get("path_restrictions", {}),
                                          out_path_restrictions=scope.get("out_path_restrictions", {}))
    except Exception:
        pass
    if not _scope_obj:
        return False
    def _route(route):
        try:
            if _scope_obj.in_scope_host(route.request.url):
                route.continue_()
                return
        except Exception:
            pass
        route.abort("blockedbyclient")
    page.route("**/*", _route)
    return True


def screenshot(url, output_path, slug=None, ident=None, wait=4, timeout=15000, scope=None):
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
        _install_scope_blocker(page, scope)
        try:
            page.goto(url, timeout=timeout, wait_until="networkidle")
        except Exception:
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
        page.wait_for_timeout(wait * 1000)
        page.screenshot(path=output_path, full_page=True)
        b.close()
    return output_path


def dom_xss_probe(url, params=None, timeout=10000, scope=None):
    """Probe URL for DOM-based XSS by injecting canary into URL params and hash.
    Returns list of findings [{param, sink, evidence}]."""
    if scope:
        try:
            import scope as _scope_mod
            s = scope if isinstance(scope, _scope_mod.Scope) else _scope_mod.Scope(scope.get("in_scope", []))
            if not s.in_scope_host(url):
                return []
        except Exception:
            return []
    from playwright.sync_api import sync_playwright
    canary = "xRay0xDOM"
    findings = []
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context()
        page = ctx.new_page()
        _install_scope_blocker(page, scope)
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


def csrf_check(url, slug=None, ident=None, timeout=10000, scope=None):
    """Check if a page has CSRF protection on its forms.
    Returns list of unprotected forms [{action, method, has_token}]."""
    if scope:
        try:
            import scope as _scope_mod
            s = scope if isinstance(scope, _scope_mod.Scope) else _scope_mod.Scope(scope.get("in_scope", []))
            if not s.in_scope_host(url):
                return []
        except Exception:
            return []
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
        _install_scope_blocker(page, scope)
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
    _scope_obj = None
    if a.slug:
        try:
            from scope import Scope as _Scope
            _base = os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements"))
            _tgt = os.path.join(_base, "_targets", a.slug + ".json")
            if os.path.isfile(_tgt):
                _scope_obj = _Scope.load(_tgt)
        except Exception:
            pass
    if not _scope_obj and a.scope:
        _scope_obj = {"in_scope": a.scope}
    if not _scope_obj and not a.scope:
        print("WARNING: no --scope or --slug — browser requests are NOT scope-enforced", file=sys.stderr)
    reqs = capture(a.url, slug=a.slug, ident=a.ident, scope_hosts=a.scope or None,
                   wait=a.wait, scope=_scope_obj)
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
