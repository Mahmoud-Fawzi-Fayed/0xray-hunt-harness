---
name: hunt-mfa-bypass
description: "Hunt MFA / 2FA bypass — step skip, missing step-up on email/password/reset/SSO, OTP reuse, empty or null OTP, OTP leaked in send/issue JSON, rate-limit classification without keyspace exhaustion, OTP consume race, recovery-code leak, factor downgrade, remember-device, WebAuthn skip, magic-link skip. Validate: attacker session reaching post-MFA state. Use when hunting auth bypass, MFA flows, chaining primitives toward ATO."
---

# HUNT-MFA-BYPASS — MFA / 2FA

## Rails
- In-scope only. Use **your** test accounts. Never send OTP guesses against a third-party mailbox.
- **No keyspace exhaustion.** A 6-digit OTP is 10^6 — do **not** ffuf 000000–999999. Prove “no effective rate limit” with a **small burst on your pending-MFA session**, then report reachability math (`hunt-brute-force`).
- No destructive lockouts of other users. One proof, then stop.
- STOP at draft. Claim only a session that reached **post-MFA state** without a valid second factor you were entitled to reuse.

## Decision tree (any MFA stack)
Fingerprint the factor: TOTP, SMS/email OTP, push, WebAuthn/passkey, backup codes, “remember this device”, recovery email. Then for **every** post-password state transition:

1. Can you **skip** the MFA step (direct URL / API / other verb / other version / password-reset complete / each SSO login)?
2. Is MFA **missing** on a sensitive mutation (email, password, OAuth link, disable-MFA, recovery codes)?
3. Is the OTP **bound** (one-time, purpose-bound, session-bound, rate-limited)?
4. Can you **downgrade** to a weaker factor (SMS, email, backup) or disable MFA without step-up?
5. Does a **client-only** check decide success (`success:true` in JSON the server never re-validates)?

Run every branch that exists. Do not stop at the first 401 on `/mfa`.

## Pattern matrix

| # | Pattern | Probe | Confirm |
|---|---|---|---|
| 1 | **Step skip** | After password, app sets pre-MFA cookie and 302s to `/mfa`. Hit `/dashboard`, `/api/me`, `/graphql`, mobile API, `/admin` with that cookie. Try other API versions (`/v1/` vs `/v2/`), `X-Original-URL`, method override. | Post-MFA resource returns **your unique identity marker** without OTP. Body-diff vs truly unauthenticated. |
| 2 | **No MFA on sensitive endpoints** | From a **password-only** or already-authed session: change email, change password, generate API tokens, disable MFA, view backup codes, **enroll attacker TOTP/WebAuthn**, add OAuth IdP. | State change succeeds with no OTP/WebAuthn challenge. Then chain to reset (`hunt-ato`). |
| 3 | **OTP reuse / not invalidated** | Complete MFA with code C on session A. Logout. Login again. Submit **the same** C (within window). Also: use C on session B while A is in-flight. | Second success = OTP not one-time. |
| 4 | **No effective rate limit** | On **your** pending-MFA session: ~20–50 wrong OTPs. Classify hard lockout / IP throttle / CAPTCHA / **silent shadow-throttle** (`hunt-brute-force` 4-state table). Seed a **known-good** OTP at the end of the burst — if it still works, limit is absent or header-bypassable. | Report math: throughput × OTP lifetime vs 10^6. **Do not** exhaust the keyspace. |
| 5 | **Race on consume** | Same OTP, **20+ concurrent** HTTP/2 streams (Turbo Intruder single-packet), not 2 sequential requests. | >1 success, or 1 success + N “already used” on the same code. |
| 6 | **Recovery / backup dump** | `GET /api/me`, `/users/current`, GraphQL `viewer { backupCodes mfaSecret }`, mobile `/settings`. IDOR the same fields (`hunt-idor`). | Plaintext backup codes, TOTP seed, or recovery email. Using **one** backup code on a test account proves login. |
| 7 | **Remember-device / trust cookie** | Complete MFA, capture device cookie. Replay from new IP/UA **without** OTP. Bindings to test: IP, UA, `Sec-CH-UA`, TLS fingerprint. | MFA skipped from a second environment. |
| 8 | **Factor downgrade** | Enroll TOTP+WebAuthn; request SMS/email fallback; `preferred_mfa=sms`; `/mfa/challenge` with `type=sms`. Disable WebAuthn via API that UI hides. | Weaker factor issued or MFA turned off without step-up. |
| 9 | **Client-side success** | Wrong OTP → intercept `{"ok":false}` / 401 → flip to `{"ok":true}` / 200. If SPA proceeds, **re-request** a protected API — server must also be fooled. | Server issues post-MFA cookie/JWT, not just UI skip. |
| 10 | **WebAuthn / passkey skip** | Drop `PublicKeyCredential`; POST `/webauthn/verify` empty; call the JSON login-complete endpoint the SPA hits **after** `navigator.credentials.get`. Origin/rpId mismatch if you control a trusted origin (`hunt-cors` / takeover). | Session without a real assertion. |
| 11 | **Purpose-unbind** | Password-reset OTP accepted on login MFA; email-change OTP accepted on disable-MFA (same 6 digits, different purpose). | Cross-purpose verify succeeds. |
| 12 | **Empty / typed OTP** | On the verify call: omit the field, `""`, `null`, `[]`, `{}`, `true`, `0`. Also `otp=000000&otp=` pollution (wrong code and empty). | Post-MFA session. A 400 or "invalid code" is not a bypass. |
| 13 | **Recovery or SSO skips MFA** | Finish password reset, magic-link / passwordless, and each OAuth/SSO login, on an account that has TOTP on password login. | That path's cookie/JWT reads the same post-MFA resource a TOTP login reads. |
| 14 | **Wide TOTP window** | Submit one code you already displayed, from several 30s steps outside the current slot. Not a search. | A code older than ±1 step still reaches post-MFA state. |
| 15 | **OTP / seed in the issue response** | `POST /mfa/send`, `/otp/request`, GraphQL `sendCode`. Read JSON (and the next page's `__NEXT_DATA__` / mobile body). | Body contains the digits or TOTP `secret`. Submitting **that** value on your account proves it. Reflection of `****` is not a leak. |
| 16 | **Pre-MFA session not rotated** | Capture the pre-MFA cookie value. Complete OTP from a second browser/profile **on the same cookie**. Compare the value before and after. | Cookie unchanged after MFA → plantable via fixation (`hunt-session`): a victim who completes MFA on your planted pre-MFA session hands you a post-MFA session. |

### Step skip
```bash
# After first factor, cookie jar holds pre-MFA session — do not follow /mfa
curl -s -b "$PRE_MFA_JAR" https://$TARGET/api/me
curl -s -b "$PRE_MFA_JAR" https://$TARGET/dashboard
curl -s -b "$PRE_MFA_JAR" -H 'Content-Type: application/json' \
  -d '{"query":"{ viewer { email mfaEnabled } }"}' https://$TARGET/graphql
```

### Sensitive endpoint without step-up
```bash
curl -s -X POST https://$TARGET/api/account/disable-mfa -H "Cookie: $SESSION" -d '{}'
curl -s -X PUT https://$TARGET/api/user/email -H "Cookie: $SESSION" \
  -H 'Content-Type: application/json' -d '{"email":"attacker@ex.com"}'
curl -s -X POST https://$TARGET/api/account/password -H "Cookie: $SESSION" \
  -H 'Content-Type: application/json' -d '{"new_password":"NewPass!2"}'
```

### OTP reuse + small rate-limit probe (your account only)
```bash
# 1) Reuse: submit the OTP you just used on a fresh login
# 2) Limit: 25 wrong codes, then the REAL current OTP last
for i in $(seq 1 25); do
  otp=$(printf '%06d' "$i")
  curl -s -o /tmp/mfa -w "%{http_code} %{time_total} %{size_download}\n" \
    -X POST https://$TARGET/api/mfa/verify -H "Cookie: $PRE" \
    -H 'Content-Type: application/json' -d "{\"otp\":\"$otp\"}"
done
# Then submit the real OTP. If it still authenticates → not shadow-throttled.
# Push / number-matching: same burst on your account only. If every push is still
# delivered, quote throughput. Do not prompt another person.
```

### Race (same OTP, many streams)
Fire ≥20 last-byte-synced requests of **one** valid OTP (`hunt-race-condition`). More than one success on that code is the bug. This is not an OTP search.

## Validation
- **Post-MFA state:** `/api/me` (or equivalent) returns the same identity marker as a legitimately MFA’d session. Status-only 200 on an SPA shell is not enough (body-diff).
- **Server-side:** flipping JSON in Burp only counts if a **new** request with the resulting cookie/JWT hits a protected API.
- **Rate limit:** 4-state classification + known-good seed. Quote throughput × lifetime vs 10^6. Never claim “I brute-forced OTP” without that math — and never actually exhaust it.
- **Race:** n≥20 concurrent, not 2. Unique marker in success body.
- Standalone MFA skip **when you already have the password** is typically **High**, not Critical, unless you also show a password-oracle / reset / cookie-theft entry (`hunt-ato`).

**Severity:** skip MFA on login → session = **High–Critical** (Critical if first factor is also bypassed or password not required). Disable-MFA / email-change without step-up → ATO chain = **Critical** when the entry cookie is obtainable in-scope. OTP reuse = **High**. Rate-limit gap with reachability math = **High–Critical**. Client-only UI skip with server still requiring OTP = **not a finding**.

## Chains
| Primitive | Compose into | Impact |
|---|---|---|
| Step skip | Password spray is **out of rails** — instead pair with reset/IDOR/JWT (`hunt-ato`) | ATO without 2FA |
| No step-up on email/password | Stolen session (XSS/CSWSH/fixation) | Persistent ATO, victim locked out |
| Backup codes in `/api/me` | IDOR or XSS | MFA satisfy without OTP |
| Remember-device unbound | Cookie theft | MFA-less login from anywhere |
| Race on OTP | One sniffed/guessed code, double spend | ATO + victim still logs in |
| Downgrade to SMS | SIM-swap is out of scope; **in-app** downgrade without step-up is the bug | Weaker factor |
| SSO or reset skips MFA | Password login still requires TOTP | ATO path that never sees the factor |
| Empty OTP accepted | Any pre-MFA session (reset, XSS, fixation) | Login without a second factor |
| OTP in send JSON | Password-only session | MFA satisfied with the leaked code |
| Magic-link / passwordless skips MFA | Inbox you control | ATO path that never sees TOTP |
| Pre-MFA cookie not rotated | Session fixation (`hunt-session`) | Victim's OTP upgrades your planted session to post-MFA |

Cross-refs: `hunt-ato`, `hunt-brute-force`, `hunt-race-condition`, `hunt-auth-bypass`, `hunt-session`, `hunt-idor`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
