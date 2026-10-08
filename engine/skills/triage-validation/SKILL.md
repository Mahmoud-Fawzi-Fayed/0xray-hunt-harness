---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Use BEFORE writing any report. One wrong answer = kill the finding and move on. Saves N/A ratio.
---

# TRIAGE & VALIDATION

One wrong answer = **kill this finding** (not the hunt). Cover remaining classes (`redteam-mindset`).

STOP at **draft**. Never auto-submit. Claim **only** what the PoC proved.

## Rails
- In-scope production (or explicitly in-scope staging). Third-party SaaS the org merely uses = OOS unless listed.
- No theoretical impact, no inflated CVSS, no “could potentially”.
- Proof types: **unique marker**, **body-diff**, **n≥10 timing**, **OOB callback**. Status-only / error-only / reflection-only fails Q6.

## 7-Question Gate (in order)

### Q1 — Can an attacker use this RIGHT NOW?
```
1. Setup:   [own account / second test id / none]
2. Request: [method, URL, headers, body — copy-paste]
3. Result:  [read/modify/delete] [exact marker in response]
4. Impact:  [ATO / PII / money / admin] — one sentence, past tense
5. Cost:    time, $0 extra
```
Cannot write step 2 as a real HTTP(S) or browser action → **kill**.

### Q2 — Does the program pay for this impact?
Read the program’s accepted types / OOS. Map to **their** list, not a generic CVSS table. Listed exclusion → **kill**.

### Q3 — In-scope asset?
Vulnerable host on the scope list. Not `*.internal` unless listed. Not a vendor portal unless in scope.

### Q4 — Privileged-precondition honesty
- “Admin can do admin things” = **kill** (intended).
- “Low-priv can do admin things” = valid.
- “Needs victim’s cookie” without an in-scope way to get it → **not Critical**; see `triage-rtfs` (may still be Medium if the mutation is itself broken **and** you state the precondition).
- Physical access / victim’s MFA device you don’t have = usually invalid.

Do **not** kill a real chain just because it has **three documented steps** (e.g. IDOR email → reset → login). Preconditions ≠ complexity tax. Kill **ungotten secrets**, not multi-step ATOs you fully ran.

### Q5 — Known / intended?
Hacktivity, changelog, API docs, prior reports. Documented-as-designed → **kill**. Regression of a **fixed** bug is valid (say so).

### Q6 — Impact beyond “technically possible”?
| Class | Minimum proof |
|---|---|
| XSS | Script runs in **victim** origin **or** cookie/token exfil OOB — not `alert(document.domain)` as Critical |
| SSRF | Internal **data** or unique OOB from an internal hop — not DNS-only |
| SQLi | Real row/file, unique marker — not a SQL error |
| IDOR | Other-user **marker** in body — not 200 |
| CSRF | Victim state changed from foreign origin |
| CORS | Browser-readable authed body |
| JWT | Forged/replayed token **does an action** |
| Timing | n≥10 (prefer 30) interleaved, median delta — not one sample |
| Blind | Unique OOB / marker |

Reflection/error/status-only → **downgrade or kill**, do not inflate.

### Q7 — Standalone-invalid class?
See lists below. Chain proven end-to-end → use the conditional table, don’t kill.

## 4 pre-submission gates
**Gate 0 Reality:** real requests, in scope, fresh-session repro, evidence file.
**Gate 1 Impact:** attacker walks away with X; victim is another user/org/money; interaction is stated.
**Gate 2 Dedup:** `python3 engine/dedup.py check ...` + hacktivity/docs. `LIKELY_DUP` unless differentiator.
**Gate 3 Quality:** title `[Class] in [endpoint] allows [actor] to [impact]`; copy-paste HTTP; evidence of impact; CVSS **and** program severity; no “may/could”.

## Standalone — usually N/A (do not file alone)
Missing CSP/HSTS/SPF/DKIM/DMARC; GraphQL introspection; banner/version without working exploit; clickjacking on non-sensitive UI; tabnabbing; CSV injection without exec; `ACAO: *` without credentialed browser read; **logout CSRF**; self-XSS; **open redirect without token/ATO/SSRF chain**; public-client `client_secret` in SPA/APK; SSRF DNS-only; Host header without reset/cache/SSRF proof; rate limit on search/contact; mixed content; weak ciphers; missing HttpOnly/Secure **without** sink; broken links; autocomplete; internal IP in an error **without** a usable pivot.

## Conditionally valid — prove the chain
| Primitive | Chain | Result |
|---|---|---|
| Open redirect | OAuth `redirect_uri` → code at OOB | ATO |
| Clickjacking | Sensitive action + working UI PoC | Medium |
| CORS | Credentialed browser read of PII/token | High |
| CSRF | Email/password/IdP/money | High+ |
| Rate-limit gap | Reachability **math** on OTP/reset (no exhaust) | High+ |
| SSRF DNS | Internal body / cloud metadata marker | Medium+ |
| Host header | Reset email link is OOB | High |
| Session survives logout/reset | Body-diff identity + theft or reset chain | Medium–High (`hunt-session`) |
| Concurrent sessions | “Logout all” / password change leaves sibling live | High if ATO multiplier |
| Pre-account takeover | You hold B’s email path when B signs up | High/Critical |
| Subdomain takeover | OAuth callback / cookie `Domain=` | Critical |
| GraphQL introspection | IDOR/authz mutation on a real field | High |
| Self-XSS | CSRF/clickjack to victim | Medium |

**Session not invalidated on logout** and **concurrent sessions** are **not** auto-N/A — they are `hunt-session` findings when body-diff proves the old cookie still returns **identity**. Severity follows that skill.

## Pre-severity (Critical/High)
Write one-liners:
1. Full chain attacker-attainable, every hop executed?
2. Walk-away sentence in past tense?
3. Reproduced **twice**?
4. Any remaining audience/sig/ownership gate?
5. Has this program capped this class?

Unsigned JWT that still fails issuer/audience is **not** Critical. Primitive ≠ chain.

## CVSS 3.1 snapshot
Use as a **starting** vector; the program’s table wins.

| Finding | Typical |
|---|---|
| IDOR read PII (auth) | 6.5 M  `PR:L C:H` |
| IDOR write | 7.5–8.1 H |
| Unauth admin / any-user ATO | 9.8 C |
| Stored XSS cookie theft | 7.6–8.5 (UI:R vs UI:N — pick and **defend**) |
| SQLi dump | 9.1 C |
| SSRF metadata | 8.5–9.1 |

`PR:N` only if no account needed. `UI:R` if a click is required. Don’t copy a 9.8 onto a login-CSRF.

## Anti-patterns
Report-before-repro; theoretical impact; extra JSON fields that aren’t sensitive; stuffing two bugs into one (split for payout); “similar to my other report” without a fresh Gate 0; overclaim; under-describe.

## Retraction
If it stops reproducing: append a retraction block (signal, disproof, why it looked real, date). Self-retract beats triager N/A. Patterns: non-unique marker; status-only 200 with identical body; policy deny-list mistaken for an oracle; n=1 timing.

## Related
`report-writing` after all gates pass; `bugcrowd-reporting` for VRT; `evidence-hygiene` for capture; `triage-rtfs` for stolen-secret preconditions; `dedup-novelty`.

## Dedup
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → draft. Never submit without approval.
