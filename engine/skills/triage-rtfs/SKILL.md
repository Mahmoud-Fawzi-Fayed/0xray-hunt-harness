---
name: triage-rtfs
description: "Pre-submission gate to avoid RTFS / Informative / N/A closures and lost ranking points. The single most common RTFS cause is a hypothetical precondition: the impact assumes an attacker already holds a victim's secret (session cookie, transaction/order/invoice id, token) that the PoC never demonstrates obtaining. Use BEFORE drafting or submitting ANY finding, on any program. Enforced in code by engine/disposition.py + engine/verify.py; this skill is the methodology."
sources: 0xray-authored
---

# TRIAGE-RTFS — don't get closed as RTFS / Informative / N/A

A report is closed (and you lose ranking points) when the impact is **hypothetical** — it depends on
something the PoC never proves. This gate catches that *before* you submit. It is generic — it applies
to every program and every class.

## The one rule that kills most reports
**If the impact starts from "an attacker who obtains X" (a victim's session cookie, a transaction id, an
order/invoice id, a token), you MUST show how the attacker obtains X — from in-scope evidence — or it's
RTFS.** Programs treat sessions and high-entropy ids as protected-until-proven-otherwise.

## The precondition ladder (weakest → strongest)
| How the attacker gets the secret | Verdict |
|---|---|
| "anyone who obtains the session" / cookie theft / malware / shared machine / MITM | **RTFS** — never demonstrated |
| leaked id asserted via webhooks / receipts / public code, but "leakage rate unquantified" | **RTFS** — asserted, not shown |
| unguessable id (UUID/ULID) whose only copies are ones the product already gives the holder, or from web.archive.org | **Informative** — capability URL, not an authz bypass |
| **in-scope response hands you another user's id** (list endpoint / oracle) → then you use it cross-account | **VALID** |
| **id is enumerable** (sequential / low-entropy) → you read another user's object | **VALID** |
| **session theft / CSRF actually reproduced** (XSS fired, `document.cookie` read, SameSite=None cross-site POST) | **VALID** |
| **write succeeds past the terminal lock** (billed/completed/paid object still mutated) | **VALID** |

## Self-check before you draft (answer all)
1. Does the PoC run **only on my own account/data**? If yes, what makes it cross a trust boundary?
2. Where does the attacker get the victim's session/id/token? **Point to the in-scope evidence.**
3. Is the id guessable/enumerable, or did an in-scope response disclose it? If neither → likely RTFS.
4. Does the write still work after the object is billed/completed/paid? If it stops → likely Informative.
5. Is the impact stated as something that *actually happened* in the PoC, not "could"?

## Run the gate (enforced in code)
```bash
python3 engine/verify.py check --file finding.json --program <program>   # includes the disposition gate
python3 engine/disposition.py check --file finding.md                     # RTFS/Informative shape alone
```
`verify` returns READY / NEEDS_FIXES / DO_NOT_SUBMIT; `disposition` returns PASS / HOLD_RTFS /
HOLD_INFORMATIVE. **A HOLD or DO_NOT_SUBMIT means do not report it as-is** — go get the missing
precondition proof first.

## How to rescue a held finding
- **Own-session ATO** → prove the entry point: an XSS that reads the cookie, a CSRF that performs the
  action cross-site, or session fixation. Without it, it's "the account acting as itself."
- **Leaked-id IDOR** → find an **in-scope oracle** that lists another user's id, or show the id is
  **enumerable**; then demonstrate the cross-account read/write with two of your own accounts.
- **Capability URL** → show the id is *not* actually a secret (enumerable, or disclosed by an in-scope
  endpoint to someone who shouldn't have it).

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator.

Cross-references: `triage-validation`, `report-writing`, `evidence-hygiene`, `ywh-triager-grade-reports`.
