---
name: triage-rtfs
description: "Pre-submission gate to avoid RTFS / Informative / N/A closures and lost ranking points. The single most common RTFS cause is a hypothetical precondition: the impact assumes an attacker already holds a victim's secret (session cookie, transaction/order/invoice id, token) that the PoC never demonstrates obtaining. Use BEFORE drafting or submitting ANY finding, on any program. Enforced in code by engine/disposition.py + engine/verify.py; this skill is the methodology."
sources: 0xray-authored
---

# TRIAGE-RTFS — Hypothetical-precondition gate

A report dies as **RTFS / Informative / N/A** when impact depends on a secret the PoC never obtains. Run this **before** drafting. Generic — every program, every class.

STOP at draft. Never auto-submit.

## The one rule
**If the story starts with “an attacker who has X” (victim cookie, invoice UUID, reset token, OTP, CSRF token), you must show an in-scope way to get X — or rewrite/drop.**

Sessions and high-entropy IDs are **protected until proven otherwise**.

## Precondition ladder (weakest → strongest)

| How attacker gets the secret | Verdict |
|---|---|
| “Anyone who obtains the session” / malware / MITM / shared PC | **RTFS** |
| “Leaked in webhooks/receipts/Wayback” without showing the leak **in-scope now** | **RTFS** |
| Unguessable UUID/ULID the product **only** shows the owner (capability URL) | **Informative** unless you show extra disclosure/enum |
| **In-scope response lists another user’s id** (or oracle) → cross-account use | **VALID** |
| **Id enumerable** (sequential / measured low entropy) → other user’s object | **VALID** |
| **Theft actually reproduced** (XSS reads cookie, CSWSH, CSRF from foreign origin, fixation) | **VALID** |
| **Write past a terminal state** (paid/billed object still mutated) | **VALID** |
| OOB unique callback **received** the token/code | **VALID** |

## Decision tree by class
Walk the class you are about to draft. Answer with evidence pointers, not vibes.

| Class | RTFS shape | Rescue |
|---|---|---|
| **IDOR** | “Given victim’s UUID…” | Show list endpoint, email/export leak, sequential enum, or GraphQL connection that **hands you** the id |
| **ATO / reset** | Host header reflected but email link still on real domain | Read **inbox**; token must hit your host |
| **ATO / cookie** | Password change without step-up **as the account** | Pair with XSS/CSWSH/fixation **or** downgrade to “no re-auth” Medium |
| **CSRF** | You replayed with victim cookie in curl | Browser PoC, other origin, cookies ambient |
| **CORS** | curl shows `ACAO` | Browser `credentials: include` read |
| **JWT** | Decoded `role:admin` | Server **accepted** forge and did an action |
| **OAuth** | `redirect_uri` accepted by server | Browser landed + **code in OOB** + exchange |
| **Open redirect** | 302 to evil | Chain to token/OAuth/SSRF or expect Low/N/A |
| **SSRF** | Collaborator DNS only | Internal body / metadata marker |
| **XSS** | Self-XSS / `alert` on your origin | Victim origin execution or exfil OOB |
| **Rate limit** | “Could brute 10^6” | Math + small-burst proof — **no** exhaust; don’t claim you guessed a **victim** OTP |
| **Session** | Survive logout on **your** cookie | That’s valid **persistence**; ATO needs a theft primitive |
| **SAML/MFA** | XML/OTP changed in a proxy while you own the login | Must change **identity/role** for a user you shouldn’t be; don’t claim any-user without that |

## Self-check (all yes/no)
1. Does the PoC run **only on my data**? If yes, what trust boundary did I cross?
2. Where does the attacker get the victim’s session/id/token? **Cite in-scope evidence.**
3. Is the id guessable **or** disclosed to the wrong principal? If neither → likely RTFS.
4. Does a write still work after billed/completed/paid? If it stops at “draft” → maybe Informative.
5. Is impact **what happened in the PoC**, not “could”?
6. Unique marker / body-diff / n≥10 / OOB — which one is attached?

## Engine gate
```bash
python3 engine/verify.py check --file finding.json --program <program>
python3 engine/disposition.py check --file finding.md
```
READY vs NEEDS_FIXES / DO_NOT_SUBMIT. HOLD_RTFS / HOLD_INFORMATIVE → **do not draft as-is**. Get the missing hop.

## Rescue
- **Own-session “ATO”** → add XSS/CSRF/fixation **or** retitle as missing re-auth on password/email (no full ATO).
- **Leaked-id IDOR** → find an oracle/list/enum; two **your** accounts.
- **Capability URL** → prove the id is **not** a secret (enum or disclosed to outsiders).
- **OAuth accept without navigation** → Playwright final host + captured `code`.

## Dedup
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. Cross-refs: `triage-validation`, `report-writing`, `evidence-hygiene`.
