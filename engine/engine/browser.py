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


def capture(url, slug=None, ident=None, scope_hosts=None, wait=6, timeout=25000, max_req=500):
    """Render url and return captured requests [{method,url,type}] (XHR/fetch/doc/script/other), scope-filtered."""
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
                key = (r.method, r.url.split("?")[0])
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
        except Exception as e:  # noqa: BLE001
            reqs.append({"_nav_error": str(e)[:160]})
        b.close()
    if scope_hosts:
        def ok(x):
            h = urlparse(x.get("url", "")).hostname or ""
            return any(h == s or h.endswith("." + s) for s in scope_hosts)
        reqs = [r for r in reqs if r.get("_nav_error") or ok(r)]
    return reqs


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
