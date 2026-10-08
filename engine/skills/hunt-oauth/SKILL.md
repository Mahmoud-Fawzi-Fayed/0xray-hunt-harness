---
name: hunt-oauth
description: Hunting skill for oauth vulnerabilities — redirect_uri bypass, PKCE skip, state/CSRF, dirty dancing, nOAuth email bind, token mix-up, open dynamic client registration (DCR). Built from 19 public bug bounty reports. Use when hunting oauth on any target.
sources: github, hackerone_public, salt_labs, descope, detectify_labs, harel_research
report_count: 19
---

# HUNT-OAUTH — OAuth 2 / OIDC

## Rails
- In-scope only. Use **your** IdP apps / test users. Do not phish real users.
- Read-only mapping first; live authorize/token only with accounts you own.
- No stuffing, no secret-cracking. Stolen `client_secret` from a **confidential** server app is a finding; secret in a **public** native/SPA client is usually expected (PKCE is the control).
- STOP at draft. `state` reflected without code/token theft is Low.

## Decision tree
1. Discover: `/oauth/authorize`, `/connect/authorize`, `/oauth/token`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, social buttons, mobile `redirect_uri`/intents.
2. Record `client_id`, registered `redirect_uri`s, `response_type`, `response_mode`, PKCE, `state`/`nonce`, `scope`.
3. Yield order: **open DCR (free redirect_uri) → redirect_uri bypass → open-redirect chain → state/CSRF → PKCE skip → token mix / aud → response_type swap (dirty dancing) → mobile/deep link → email-claim bind (nOAuth)**.
4. Every “server accepted this redirect_uri” **must** be checked in a **browser**: WHATWG navigation vs string match (`hunt-open-redirect`).
5. Impact = **code or token in your hands, exchanged as B** — or B’s account **linked** to A’s IdP.

## Surface
```
/oauth/authorize /oauth/token /connect/authorize /auth/callback /oauth/callback
/device /par  .well-known/openid-configuration
redirect_uri client_id response_type=code|token|id_token  code_challenge
state nonce response_mode=web_message|form_post  scope
```

## Attack matrix

| # | Class | Probe | Confirm |
|---|---|---|---|
| 1 | **redirect_uri** | See bypass list. Pair with open redirect on allowlisted host. | Browser lands on **your** host **with** `code`/`token`. OOB log. |
| 2 | **state CSRF / account link** | Drop `state`; reuse A’s `state`; bind not tied to session. Force B (logged in) to A’s callback. | B linked to A’s IdP → A logs in as B (`hunt-ato`). |
| 3 | **PKCE skip / downgrade** | Omit `code_challenge`; swap `S256`→`plain`; exchange code **without** `code_verifier`; use verifier from another flow. | Token issued. Public clients must enforce PKCE. |
| 4 | **response_type / mode swap** | `token` / `id_token` where only `code` was intended; omit `nonce` on `id_token`/hybrid; `response_mode=web_message` + loose `postMessage`; `form_post` to attacker origin. | Token in fragment, postMessage, or POST body to you. Replay of an `id_token` minted without `nonce` still logs you in. |
| 5 | **Code replay / mix-up** | Replay `code` on token endpoint; send code+`client_id` of app A to app B’s token URL. Drop or swap `iss` on the authorization response (RFC 9207). | Access token for the wrong client / wrong user. |
| 6 | **Pass-the-token / aud** | Facebook/Google token minted for **your** app posted to target’s social-login API. Token `aud`/`app_id` not checked. | Session as the email in that token (`nOAuth` / Salt Labs class). |
| 7 | **Unverified email bind** | Mutable IdP `mail` / `email` claim (Azure AD nOAuth). RP keys users by email. | ATO of victim email you set on **your** IdP tenant (lab). |
| 8 | **Referer / logs** | `code` or `access_token` in query; callback page loads 3rd-party img/script. | Referer or analytics has the secret (Network tab / OOB). |
| 9 | **Mobile / intent** | Custom scheme or `intent://` WebView `url=` without host allowlist. | Token/cookie in WebView you control (your device). |
| 10 | **Token endpoint authz** | `grant_type=password` with unverified user; skip email-verify; `client_credentials` scope too wide. | Full-scope token without completing UI checks. |
| 11 | **Device / PAR / DPoP** | Device-code `user_code` entropy + limiter (`hunt-brute-force` math only); PAR `request_uri` swap; DPoP skipped → bearer still accepted. | Token without the extra binding. |
| 12 | **scope / incremental** | Authorize `scope=openid`; token replay with added `scope=email offline_access` on `/token` or silent iframe. | Extra scopes granted. |
| 13 | **redirect_uri not bound** | Authorize with registered URI A. Exchange the code with URI B, or omit `redirect_uri`. | Token issued. Without a leaked code this is the binding bug, not ATO yet — say which. |
| 14 | **Refresh reuse** | Exchange RT1, receive RT2. Send RT1 again. | RT1 still returns an access token, or reuse does not revoke the family. `GET` a user resource with the new token. |
| 15 | **Loopback on a web client** | `redirect_uri=http://127.0.0.1:<port>/cb` on a **browser** client. Native-app loopback is often spec-legal; do not report that alone. | The authorization code hits a listener you opened. |
| 16 | **Open DCR (RFC 7591)** | `POST /register` (also `/oauth/register`, `/connect/register`, `registration_endpoint` from `/.well-known/openid-configuration`) with **your** `redirect_uris` and `token_endpoint_auth_method=none`. No auth header. | `201` + `client_id`, then an authorize of **your** test user lands `code` on **your** URI. Registration alone is not ATO — complete the exchange. `javascript:` / `data:` URIs are XSS if the AS later redirects there (`hunt-xss`). |

### redirect_uri payloads
```
https://evil.com#legit.com
https://legit.com.evil.com
https://legit.com@evil.com          # only if @ still in authority
https://legit.com%2eevil.com
https://legit.com/cb/../../../evil
https://legit.com/cb?next=https://evil.com   # open-redirect chain
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb
https://oauth.xn--...homograph...
https://legit.com%2F@evil.com
```
IDN homograph, suffix match, path traversal after validate, parameter pollution — try each **once**.

### Browser vs server (do not skip)
| Server check | URL | Browser host | ATO? |
|---|---|---|---|
| prefix `https://acme.example` (no slash) | `https://acme.example@evil.com/cb` | evil.com | **Yes** if code attached |
| prefix `https://acme.example/` | `https://acme.example/@evil.com/cb` | acme.example (`@` in path) | **No** |
| substring | `https://acme.example.evil.com/cb` | attacker | **Yes** |

Headless-navigate before claiming ATO.

### State / link CSRF
```bash
# A obtains code; B (logged-in) visits:
# https://target/oauth/callback?code=A_CODE&state=
```

### Open DCR
```bash
REG=$(curl -s "$TARGET/.well-known/openid-configuration" | jq -r '.registration_endpoint // empty')
curl -s -D - -X POST "${REG:-https://$TARGET/register}" \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["https://UNIQUE.oastify.com/cb"],"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"]}'
# Then run authorize with the returned client_id and that redirect_uri. Code on UNIQUE = proven.
```

### PKCE skip
```bash
curl -s -X POST https://$TARGET/oauth/token \
  -d grant_type=authorization_code -d code="$CODE" \
  -d client_id="$CID" -d redirect_uri="$URI"
# omit code_verifier — success = PKCE not enforced

# Code was issued for URI A. Exchange it with a different registered URI.
curl -s -X POST https://$TARGET/oauth/token \
  -d grant_type=authorization_code -d code="$CODE" \
  -d client_id="$CID" -d redirect_uri="$OTHER_URI"

# RT1 was already rotated to RT2. This must fail. A new access token is the bug.
curl -s -X POST https://$TARGET/oauth/token \
  -d grant_type=refresh_token -d refresh_token="$RT1" -d client_id="$CID"
```

## Validation
- **Token/code in your control** + successful **exchange** + session **as B** (unique marker).
- OOB: unique callback host logged the query/fragment (fragment needs JS on your page).
- Account-link: B’s login-with-IdP now signs **A** in.
- Open DCR: minted `client_id` + **your** test-user `code` on the registered URI. A 201 from `/register` with no authorize is not ATO.
- `client_secret` in SPA/APK = expected for public clients unless you also skip PKCE or mint tokens for **other** users.
- JSON-parse errors; never substring `access_token` inside AADSTS claims.

**Severity:** code/token theft or nOAuth ATO = **Critical/High**. State-only CSRF without bind = **Medium** (login CSRF). Open redirect without token = **Low** (`hunt-open-redirect`).

## Chains
| Primitive | Compose | Impact |
|---|---|---|
| redirect_uri + open redirect | `hunt-open-redirect` | ATO |
| `*.target.com` allowlist | Dangling CNAME (`hunt-subdomain`) | Claimed callback |
| Loose postMessage | Dirty dancing | Token to parent window |
| SAML then OAuth | `hunt-saml` XSW | Admin token |
| Unverified email | Password grant | Skip verify (`hunt-auth-bypass`) |
| Open DCR | Authorize as your user with the minted `client_id` | Code/token to your URI |

## Pattern citations (public)
Semrush IDN H1 #861940; pixiv `../` H1 #1861974 ($2k); Slack suffix H1 #2575; Booking.com + Salt Labs 2023; Expo `returnUrl` CVE-2023-28131; Azure AD nOAuth (Descope 2023); Pass-the-token (Salt Labs); Zoom dirty dancing ($15k, 2024); Detectify dirty dancing 2022.

Cross-refs: `hunt-ato`, `hunt-open-redirect`, `hunt-subdomain`, `hunt-saml`, `hunt-csrf`, `hunt-jwt`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
