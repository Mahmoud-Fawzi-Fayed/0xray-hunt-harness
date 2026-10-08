---
name: hunt-brute-force
description: "Hunt Missing/Weak Rate Limiting — login brute force, OTP/2FA brute force (10^6 keyspace), password-reset-token brute, credential stuffing, username/email enumeration via error-string / status-code / timing differences, weak password policy, missing CAPTCHA, IP-based rate-limit bypass via X-Forwarded-For and friends, ReDoS. Distinguishes hard lockout vs soft IP-throttle vs CAPTCHA-injection vs silent shadow-throttling (avoids false-negative 'no rate limit' conclusions). Medium to Critical depending on what the brute reaches (OTP→ATO = Critical)."
sources: public_research
report_count: 0
---

# HUNT-BRUTE-FORCE — Missing / Weak Rate Limiting

This skill **detects** missing or bypassable rate limits. It does **not** authorize keyspace exhaustion.

## Rails (hard)
- In-scope only. **Your** test accounts only.
- **No brute-force, password-cracking, credential-stuffing, or keyspace exhaustion.** No hydra, hashcat, rockyou, 000000–999999 OTP runs, breach-corpus sprays.
- Prove the primitive **once** (small burst + classification + math). Then stop.
- **No DoS.** ReDoS: stop at the first super-linear datapoint. Do not grow payloads to knock the origin over.
- STOP at draft. Do not cite invented payouts. `report_count` is 0 by design.

## What actually pays
A **reachable** authentication secret (OTP, reset code, session) **because** the limiter is absent or bypassable — with math that a triager can check. Enumeration alone is Low/Medium unless chained.

## Four limiter states — classify before concluding
A 200/401 with no 429 is **not** “no rate limit”. Burst ~20–50 requests at **your** account; watch status, **body**, headers, latency, and whether a **known-good** value still works:

| State | Signal | Still a finding? |
|---|---|---|
| **Hard lockout** | Account disabled; even the correct password/OTP fails | Not a brute finding. Attacker-triggerable lockout of **your** account may be Medium DoS — prove once, do not lock others. |
| **Soft IP throttle** | 429 / backoff keyed on source IP | Yes **if** a client-controlled header (`X-Forwarded-For`, …) resets the counter (Phase 4). |
| **CAPTCHA injection** | Body switches to CAPTCHA after N | Yes if `/api/verify` (or mobile) **skips** the CAPTCHA the UI added. |
| **Silent shadow-throttle** | Status stays 401/200 but the **real** OTP/password stops working, or bodies become canned | **Trap.** Naive loops report “no limit”. Seed a known-good at the end. |

### Shadow-throttle detector (your OTP only)
```bash
# After ~25 wrong codes, submit the REAL current OTP for YOUR pending-MFA session.
# If the real code now fails → shadow throttle, NOT "no rate limit".
KNOWN_GOOD="123456"   # current OTP for your test account
PRE="$SESSION_COOKIE"
for n in $(seq 1 25); do
  curl -s -o /tmp/bf -w "%{http_code} %{time_total} %{size_download}\n" \
    -X POST "https://$TARGET/api/verify-otp" -H "Cookie: $PRE" \
    -H 'Content-Type: application/json' -d "{\"otp\":\"0000$(printf '%02d' "$n")\"}"
done
curl -s -o /tmp/bf -w "REAL %{http_code} %{time_total} %{size_download}\n" \
  -X POST "https://$TARGET/api/verify-otp" -H "Cookie: $PRE" \
  -H 'Content-Type: application/json' -d "{\"otp\":\"$KNOWN_GOOD\"}"
```

## Decision tree
1. Identify the **secret class**: login password, OTP/MFA, reset token, backup code, coupon, invite.
2. Classify limiter (4-state) with a **small burst**.
3. If soft-IP: test header rotation (Phase 4) — still small N.
4. If OTP/reset: measure **entropy** of tokens you were issued (Phase 5) — no guessing others’ tokens.
5. Impact = **reachability math**, not a completed brute: `throughput × lifetime ≟ keyspace`.
6. Enumeration (Phase 3) is a separate Low/Medium unless it feeds an in-scope ATO primitive.

## Phase 1 — Login limiter (classify)
```bash
for i in $(seq 1 30); do
  curl -s -o /tmp/bf_l -w "i=$i status=%{http_code} t=%{time_total} len=%{size_download}\n" \
    -X POST "https://$TARGET/api/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"YOUR_TEST@$TARGET\",\"password\":\"wrong-$i\"}"
  sleep 0.1
done
```
Then classify. “Nothing changed across 30” = **candidate**; confirm with known-good password still working (not shadow).

## Phase 2 — OTP / reset-code (probe + math, never 10^6)
```bash
# ~20 wrong codes on YOUR pending-MFA / reset session. Stop at 429/lockout/CAPTCHA.
for CODE in $(seq -f "%06g" 0 20); do
  curl -s -o /dev/null -w "$CODE %{http_code} %{time_total}\n" \
    -X POST "https://$TARGET/api/verify-otp" -H "Cookie: $PRE" \
    -H 'Content-Type: application/json' -d "{\"otp\":\"$CODE\"}"
done
```
**Impact write-up (required):**
- keyspace (e.g. 10^6 for 6 digits, 10^4 for 4 digits)
- observed req/s **before** throttle
- code lifetime / rotation
- expected attempts ≈ keyspace / 2
- Example: 20 req/s, 10-minute OTP, 6 digits → 20×600=12k ≪ 10^6 → **not** reachable. 50 req/s, **non-rotating** reset PIN, no limit → reachable in hours → Critical **math**, still do not run it.

Instagram-class 2019–2021 research (Laxman Muthiyah): 6-digit reset + no per-account limit + rotation gaps. Cite as **technique**, not a payout.

## Phase 3 — Username / email enumeration
```bash
VALID="your-user@$TARGET"; INVALID="no-such-xyz123@$TARGET"
# Status + body + length
for U in "$VALID" "$INVALID"; do
  curl -s -o /tmp/e -w "[$U] %{http_code} %{time_total} %{size_download}\n" \
    -X POST "https://$TARGET/api/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$U\",\"password\":\"wrong\"}"
done
diff <(curl -s -X POST ... valid ...) <(curl -s -X POST ... invalid ...)
```
**Timing:** n≥10 (prefer 30) interleaved valid vs invalid; compare **medians**. Single-shot is noise. Also forgot-password and register “already taken”.

Generic “if this email exists we sent a message” with **identical** bodies is **not** enumeration.

## Phase 4 — Client-controlled source bypass
```bash
HEADERS=(X-Forwarded-For X-Real-IP X-Originating-IP X-Client-IP CF-Connecting-IP True-Client-IP Forwarded)
# 20 requests, unique spoofed IP per try. Then 20 WITHOUT spoof — 429 returning is the proof.
```
Try first-vs-last in comma XFF (`1.1.1.1, 9.9.9.9`). Confirm delta; do not rotate through a password list.

## Phase 5 — Token entropy (issued to you)
Collect ≤20 reset/OTP/session values for **your** account. Decode (hex/base64); look for counter/timestamp/`userId`. `ent` / Shannon bits/char. <64 bits of **effective** entropy on a security token is the finding — plus limiter math from Phase 2.

## Phase 6 — ReDoS (one curve, then stop)
```bash
# Super-linear growth vs a same-length benign control. Stop at the first clear doubling.
for LEN in 5 10 15 20; do
  EVIL=$(python3 -c "print('a'*$LEN+'!')")
  OK=$(python3 -c "print('b'*$LEN)")
  echo -n "evil $LEN "; curl -s -o /dev/null -w "%{time_total}\n" "https://$TARGET/search?q=$EVIL"
  echo -n "ctrl $LEN "; curl -s -o /dev/null -w "%{time_total}\n" "https://$TARGET/search?q=$OK"
done
```
Linear = slow endpoint, not ReDoS. Do **not** push LEN until the origin dies.

## Validation
| Claim | Proof |
|---|---|
| No rate limit | 4-state classification + known-good still works after burst |
| OTP/reset reachable | Math (throughput × lifetime vs keyspace), **not** a completed brute |
| Enumeration | Reproducible body/status **or** n≥10 median timing delta |
| IP bypass | Throttle **returns** when spoofing is removed |
| Entropy | Structure or measured bits, not “looks short” |
| ReDoS | Super-linear vs control; one proof |

**Severity:** reachable OTP/MFA/reset → ATO path = **Critical** (math + your account demo). Login unlimited + **no** stuffing performed = **High** as a primitive (programs vary — some want the ATO chain). Enumeration alone = **Low–Medium**. ReDoS with meaningful lag = **Medium** (no availability wipe). Attacker-triggerable lockout = **Medium**.

## Chains
| Primitive | Compose | Impact |
|---|---|---|
| No OTP limit + short OTP | `hunt-mfa-bypass` / `hunt-ato` | ATO (report math) |
| Reset-code entropy | Host-header / IDOR email (`hunt-ato`) | ATO |
| Enumeration | **Do not** spray corpora | Standalone Low; useful recon only |
| XFF bypass | Any per-IP limiter | Amplifies other classes |
| ReDoS | — | Availability; do not exploit at scale |

Cross-refs: `hunt-mfa-bypass`, `hunt-ato`, `hunt-auth-bypass`, `triage-validation`, `triage-rtfs`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
