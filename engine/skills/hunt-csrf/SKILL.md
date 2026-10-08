---
name: hunt-csrf
description: Hunting skill for csrf vulnerabilities. Built from 15 public bug bounty reports including modern variants — SameSite=Lax sibling-subdomain bypass (Argo CD CVE-2024-22424), GraphQL mutations-via-GET (GitLab $3,370), framework-wide CSRF middleware disabled (Stripe Dashboard $5,000), path-traversal CSRF-token bypass (GitHub Enterprise CVE-2022-23732 $10k), Origin-omission bypass (TikTok $2,500), OAuth-state null-byte (Streamlabs), WebSocket CSRF / CSWSH (Coda), default-SameSite email-change → ATO (YoYo Games $400), social-account-link CSRF (HackerOne), JSON-CSRF via text/plain on email-change (TikTok $500). Use when hunting modern CSRF — heavy emphasis on chain-to-ATO patterns.
sources: github, hackerone_public, bugcrowd_public, github_security_advisories
report_count: 15
---

# HUNT-CSRF — Cross-Site Request Forgery

## Rails
- In-scope only. PoC from **your** attacker origin against **your** victim test session.
- State-changing tests only on accounts/objects you own. One successful action, then revert if cheap.
- No mass-CSRF, no logout-flood DoS.
- STOP at draft. Missing token on **logout** / no-impact action is N/A.

## What pays
Cross-site request, **victim’s ambient cookies**, **state change that matters** (email, password, OAuth link, transfer, delete, admin). Token-missing on a no-op is not impact.

## Decision tree
1. Map POST/PUT/PATCH/DELETE/GraphQL mutations / WS / form + AJAX. Note cookie `SameSite`, CSRF token, Origin/Referer checks, Fetch Metadata, custom headers.
2. For each **sensitive** action: omit token → foreign token → JSON via simple request → GET mutation → method override → null Origin → sibling-subdomain Lax bypass.
3. Confirm in a **browser** from attacker origin (cookies attached or not). curl can send cookies you paste — that is **not** CSRF.
4. Impact: victim account **state** changed (second channel / victim login). Then chain to ATO if email/password/IdP link.

## Surface
Session cookie without `SameSite=Strict`; `SameSite=None`; no token in POST; JSON APIs; `/oauth/callback`; account-link; GraphQL; SignalR/WS; BFF `X-CSRF: 1`.

## Cookie / SameSite (modern Chrome)
Default Lax since ~2020. **Lax sends cookies on top-level GET navigations**, not on `fetch`/XHR/form-POST from foreign origins — **except**:
- `SameSite=None; Secure` or **no SameSite** on old clients
- **Sibling subdomain** attacker (`marketing.target.com` → `app.target.com`) — often treated as schemeful-same-site / parent-domain; Lax may still send (Argo CD CVE-2024-22424 class)
- Top-level POST via 307/meta from a **same-site** hop
- Login CSRF / GET-state-change (`<img>`, `<form method=GET>`)

Always read the real `Set-Cookie`. Do not assume “Lax = safe” or “Lax = always CSRF”.

## Tests
| Test | How | Hit |
|---|---|---|
| Token omit | Drop `csrf` / `X-CSRF-Token` | Action still applies |
| Token swap | A’s token on B’s cookie (and vice versa) | Token not bound to session |
| Static token | Same value across pages/users | Leakable |
| JSON simple | `enctype=text/plain` or urlencoded POST to JSON API | No preflight, cookies sent |
| GET mutation | GraphQL `?query=mutation…`, `_method=DELETE`, `<img src>` | Lax cookies send |
| Path confusion | `/safe/../admin/users` — router vs CSRF middleware path (GHES CVE-2022-23732) | Protected handler, skipped check |
| Origin omit / null | Sandboxed iframe; HTTPS→HTTP Referer strip; some servers allow missing Origin | Check skipped |
| Weak Origin match | `target.com.evil.com` `eviltarget.com` | Naive `contains` |
| Fetch Metadata | If server requires `Sec-Fetch-Site: same-origin`, try top-level nav / `<form>` (`same-site` vs `cross-site`) | Policy bypass |
| Login CSRF | Attacker’s creds posted from victim browser | Victim logged into attacker account (session fixation sibling) |
| OAuth/SAML state | Missing `state`/`RelayState` bind | Account-link ATO (`hunt-oauth`) |
| CSWSH | Cookie WS handshake, no Origin (`hunt-websocket`) | Read/write as victim |

### Form POST PoC
```html
<body onload="document.forms[0].submit()">
<form method="POST" action="https://TARGET/settings/email">
  <input name="email" value="attacker@inbox.test">
</form>
```

### JSON via text/plain
```html
<form method="POST" action="https://TARGET/api/account/email" enctype="text/plain">
  <input name='{"email":"attacker@inbox.test","x":"' value='"}'>
</form>
```

### GraphQL GET
```html
<img src="https://TARGET/api/graphql?query=mutation{updateEmail(email:%22a@evil%22){ok}}">
```

Browser PoC must run **without** you pasting the victim cookie. Victim is logged into TARGET; attacker page is other origin (or sibling, if that is the bug).

## BFF / static header (Duende-class, any clone)
Some BFFs treat `X-CSRF: 1` as antiforgery (forces preflight) — **not user-bound**. Same-origin script + victim cookie hits admin partition. WS/SignalR often **excluded**. Cookie `Domain=.` + takeover = fixation (`hunt-session`). Report by **chain impact**, not a missing CVE.

## Validation
1. Attacker page + victim session → **named state change** (email now attacker’s, IdP linked, test object deleted).
2. Victim loses account control / money / data — not “request executed”.
3. Repro: two accounts, static HTML, victim visit, confirm in victim UI. 10 minutes, no extra preconditions beyond “logged in” (standard CSRF) or “logged in + one click”.
4. Logout / add-to-cart / harmless heartbeat = N/A unless chained.

**Severity:** email/password/IdP-link CSRF = **High–Critical** (ATO). Sensitive but not ATO = **Medium–High**. Login CSRF = **Medium** (often needs fixation/XSS). Logout = **N/A**.

## Chains
| CSRF | Compose | Impact |
|---|---|---|
| Change email | Reset password | ATO (`hunt-ato`) |
| Account-link | Attacker IdP | ATO (`hunt-oauth`) |
| No token + XSS | Token steal unnecessary | One-click ATO (`hunt-xss`) |
| Sibling Lax | Subdomain XSS/takeover | CSRF despite Lax |
| CSWSH | Token in stream | ATO (`hunt-websocket`) |

## Pattern citations
Argo CD CVE-2024-22424 (Lax + sibling); GitLab GraphQL GET H1 #1122408 ($3,370); Stripe middleware off H1 #1483327 ($5,000); GHES path traversal CVE-2022-23732 ($10k); H1 social-link CSRF H1 #1727221.

Cross-refs: `hunt-ato`, `hunt-oauth`, `hunt-xss`, `hunt-session`, `hunt-websocket`, `hunt-cors`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
