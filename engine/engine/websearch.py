#!/usr/bin/env python3
"""
websearch.py — the hunter's eyes on the open web. stdlib-only search + page-read so an agent can look
up a CVE, read vendor docs, check a disclosed report, or confirm a tech fingerprint mid-hunt without
any API key.

  search(query, n)  -> [{title, url, snippet}]   via DuckDuckGo's HTML endpoint (no key, no JS)
  fetch(url)        -> plain text of a page (tags stripped, size/time capped)

Both are defensive: short timeouts, size caps (no runaway memory), a realistic UA, and they return
[] / "" instead of raising so a hunt step never dies because the network hiccuped.

CLI:
  python3 engine/websearch.py search "paddle.com api CVE" -n 5
  python3 engine/websearch.py fetch https://nvd.nist.gov/vuln/detail/CVE-2024-0001
  python3 engine/websearch.py selftest        # offline (parses a canned SERP)
  python3 engine/websearch.py live "site:paddle.com changelog"   # real network
"""
import argparse
import html
import json
import re
import sys
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Safari/537.36")
MAX_FETCH = 1_500_000          # cap bytes read from a page
TIMEOUT = 15

_RESULT_RE = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_SNIPPET_RE = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.I | re.S)
_WS_RE = re.compile(r"[ \t\f\v]+")
_NL_RE = re.compile(r"\n{3,}")


def _strip_tags(s):
    s = _SCRIPT_RE.sub(" ", s or "")
    s = _TAG_RE.sub(" ", s)
    s = html.unescape(s)
    s = _WS_RE.sub(" ", s)
    s = _NL_RE.sub("\n\n", s)
    return s.strip()


def _unwrap_ddg(href):
    """DDG wraps result links as //duckduckgo.com/l/?uddg=<encoded>&...  -> return the real URL."""
    href = html.unescape(href or "")
    if href.startswith("//"):
        href = "https:" + href
    try:
        q = urllib.parse.urlparse(href)
        if "duckduckgo.com" in q.netloc and q.path.startswith("/l/"):
            uddg = urllib.parse.parse_qs(q.query).get("uddg", [])
            if uddg:
                return urllib.parse.unquote(uddg[0])
    except ValueError:
        pass
    return href


def parse_serp(html_text, n=8):
    """Parse a DuckDuckGo HTML results page into [{title,url,snippet}]. Pure, offline-testable."""
    out = []
    links = _RESULT_RE.findall(html_text or "")
    snips = _SNIPPET_RE.findall(html_text or "")
    for i, (href, title) in enumerate(links[: max(1, int(n or 8))]):
        out.append({
            "title": _strip_tags(title),
            "url": _unwrap_ddg(href),
            "snippet": _strip_tags(snips[i]) if i < len(snips) else "",
        })
    return out


def _get(url, timeout=TIMEOUT, max_bytes=MAX_FETCH):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(max_bytes).decode("utf-8", "replace")


def search(query, n=8, timeout=TIMEOUT):
    """DuckDuckGo HTML search. Returns [] on any failure (never raises)."""
    q = str(query or "").strip()
    if not q:
        return []
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(q)
    try:
        return parse_serp(_get(url, timeout=timeout), n=n)
    except Exception:  # noqa: BLE001 — network/parse failures must not kill the hunt
        return []


def fetch(url, timeout=TIMEOUT, max_chars=40_000):
    """Fetch a page and return readable text (tags stripped, truncated). "" on failure."""
    u = str(url or "").strip()
    if not re.match(r"^https?://", u):
        return ""
    try:
        text = _strip_tags(_get(u, timeout=timeout))
        return text[: max(500, int(max_chars))]
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- CLI
_CANNED = (
    '<div class="result">'
    '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnvd.nist.gov%2Fvuln%2Fdetail%2FCVE-2024-1234&rut=x">'
    'CVE-2024-1234 &mdash; Example <b>flaw</b></a>'
    '<a class="result__snippet" href="x">A serious issue in &amp; around the parser.</a>'
    '</div>'
    '<div class="result"><a class="result__a" href="https://example.com/doc">Docs</a>'
    '<a class="result__snippet" href="y">Second &lt;result&gt; snippet.</a></div>'
)


def _cmd_search(a):
    print(json.dumps(search(a.query, n=a.n), indent=2))
    return 0


def _cmd_fetch(a):
    print(fetch(a.url))
    return 0


def _cmd_live(a):
    r = search(a.query, n=a.n)
    print(f"live search returned {len(r)} result(s)")
    for x in r:
        print(f"  - {x['title'][:70]}\n    {x['url']}")
    return 0 if r else 1


def _cmd_selftest(_a):
    r = parse_serp(_CANNED, n=5)
    assert len(r) == 2, r
    assert r[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", r[0]
    assert "flaw" in r[0]["title"] and "CVE-2024-1234" in r[0]["title"], r[0]
    assert "&" in r[0]["snippet"] and "parser" in r[0]["snippet"], r[0]      # entities unescaped
    assert r[1]["url"] == "https://example.com/doc"
    assert "<result>" in r[1]["snippet"], r[1]                                # &lt;result&gt; -> <result>
    # text stripping
    assert _strip_tags("<script>bad()</script><p>Hi <b>there</b></p>") == "Hi there"
    # hostile / empty input never raises, returns safe empties
    assert search("") == [] and search(None) == []                           # type: ignore
    assert fetch("not a url") == "" and fetch(None) == ""                     # type: ignore
    assert parse_serp(None) == [] and parse_serp("") == []
    print("websearch.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="stdlib web search + page reader for the hunter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("search"); ps.add_argument("query"); ps.add_argument("-n", type=int, default=8); ps.set_defaults(fn=_cmd_search)
    pf = sub.add_parser("fetch"); pf.add_argument("url"); pf.set_defaults(fn=_cmd_fetch)
    pl = sub.add_parser("live"); pl.add_argument("query"); pl.add_argument("-n", type=int, default=5); pl.set_defaults(fn=_cmd_live)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
