---
name: okta-attack
description: Okta-as-IdP red-team attack chain — tenant discovery, user enumeration (IDX identify / recovery — no password), authentication flow analysis (factors from IDX remediation, push-notification fatigue as OOS social-eng), lockout-disciplined credential validation (one secret, not a spray), Okta-specific phishing primitives (kits, FastPass abuse, OIDC redirect_uri tampering), MFA factor mapping, post-compromise admin API surface. Many enterprise orgs use Okta instead of (or alongside) Entra ID. Distinct endpoints, distinct rate-limiting, distinct factor flows. Use when recon shows `<tenant>.okta.com`, `<tenant>.okta-emea.com`, `<tenant>.oktapreview.com`, password spray classification against Okta, or autodiscover-style records pointing at Okta IdP.
sources: public-okta-docs, idp-redteam-knowledge, disclosed-incidents
report_count: 8
---

## When to use this skill

Trigger when:
- DNS shows `<tenant>.okta.com` or `<tenant>.okta-emea.com` (EMEA region)
- Login flow redirects to `<tenant>.okta.com/login` or `/app/<app_id>/sso/saml`
- Web pages reference `/signin/customize`, `oktapreview.com`, or `auth-js-sdk`
- Recon notes "uses Okta for SSO"
- A target has `*.okta.com` SAN in TLS cert
- Identity-fabric mapping returns Okta as IdP for a corporate app

DO NOT use for:
- Entra ID (use `m365-entra-attack` instead)
- Google Workspace (use `google-workspace-attack` — not yet built)
- ADFS (different protocol, on-prem)

---

## Tenant discovery

### Direct guesses
```bash
# Tenant subdomains often match the brand
# Replace these with your target's actual tenant slug candidates:
for tenant in target-brand target-brand-ltd target-sister-brand target-brand-short target-other-variant; do
  for region in okta okta-emea oktapreview; do
    host="$tenant.$region.com"
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "https://$host/")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $host  $code"
  done
done
```

### Cross-ref from DNS
```bash
# Look for CNAME records pointing to Okta
# Replace with your target's actual domains:
for domain in client.example client-ltd.example; do
  dig +short "sso.$domain" CNAME
  dig +short "login.$domain" CNAME
  dig +short "auth.$domain" CNAME
  dig +short "okta.$domain" CNAME
done
```

### Cross-ref from app HTTP flow
```bash
# Visit corporate-app login, follow redirects
curl -skL -o /dev/null -w "%{redirect_url}\n" "https://app.target.com/login"
# If redirects to <something>.okta.com → confirmed Okta tenant
```

### Classic vs Identity Engine
```bash
curl -sk "https://<tenant>.okta.com/.well-known/okta-organization"
# "pipeline": "idx" → Identity Engine (IDX). "pipeline": "v1" → Classic /api/v1/authn.
```
Test the pipeline you got. A Classic-only enum on an `idx` org is a false negative, and the reverse.

---

## User enumeration

### Method 1 — `/api/v1/authn` is not an existence oracle
Classic `/api/v1/authn` returns a uniform `E0000004` "Authentication failed" for both unknown users and bad passwords (2024+). It also **burns a lockout slot** if the user exists. Do not POST a password here to enumerate. Use Method 2. Interpret `E0000004` / `E0000119` / `MFA_REQUIRED` only after an RoE-authorized credential attempt (section below).

### Method 2 — Identity Engine `/idp/idx/identify` (no password)
User-enumeration prevention is **off by default**, and it stays off when self-service registration or email JIT is enabled. Compare one known-real identifier with one known-absent identifier. Do not submit a password to enumerate.

```bash
# interactionHandle: the sign-in widget's POST /oauth2/v1/interact (or the page's oktaData).
# introspect returns stateHandle. A 400 from the wrong Content-Type is not "prevention on".
curl -sk -X POST "https://<tenant>.okta.com/idp/idx/introspect" \
  -H "Accept: application/ion+json; okta-version=1.0.0" \
  -H "Content-Type: application/ion+json; okta-version=1.0.0" \
  -d '{"interactionHandle":"<from interact>"}'
curl -sk -X POST "https://<tenant>.okta.com/idp/idx/identify" \
  -H "Accept: application/ion+json; okta-version=1.0.0" \
  -H "Content-Type: application/ion+json; okta-version=1.0.0" \
  -d '{"identifier":"<email>","stateHandle":"<from introspect>"}'
```

Different `messages` / `remediation` for the real vs absent identifier means prevention is off. Identical responses mean it is on — stop, do not hammer. Recovery (`/idp/idx/challenge` or Classic `POST /api/v1/authn/recovery/password` with only `username` and `factorType`) is the same differential; one pair of probes, not a list.

### Method 3 — sessions/me is not an oracle
`GET /api/v1/sessions/me` without a session is an anonymous 404/403. It does not prove a user exists. Do not count it as enumeration.

### Method 4 — Identifier format, not a wordlist
Orgs use email, `firstname.lastname`, or an employee id. Confirm the format with **one** known employee and **one** absent string, via Method 2. Do not iterate employee ids or guess a directory.

### Method 5 — OIDC `/v1/authorize` with login_hint
```bash
# One known-real vs one known-absent. Byte-diff Location / body. Identical 302s = hardened.
curl -skI "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<id>&response_type=code&scope=openid&redirect_uri=<registered>&login_hint=<email>"
```
A single 302 is not enum. Need the pair to differ (error vs consent, or different `error_description`). Then stop — do not walk a directory.

---

## Authentication flow analysis

On `pipeline=idx`, the Method 2 `remediation` / `authenticators` list is the factor map and it does not take a password. On `pipeline=v1`, the factor array below is returned only after a **correct** password (`MFA_REQUIRED`). Do not POST a dummy password to a real user to "see the factors" — that is a lockout attempt and, since 2024, usually a uniform `E0000004` with no factor list.

```bash
# Only after an RoE-authorized attempt already returned MFA_REQUIRED. Do not send a guessed password to populate this.
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<user>","password":"<the one RoE-authorized secret>"}' | python3 -m json.tool
```

Response structure reveals factor configuration:
```json
{
  "stateToken": "00ABC...",
  "factorResult": "WAITING",
  "status": "MFA_REQUIRED",
  "_embedded": {
    "factors": [
      {"factorType": "push", "provider": "OKTA"},
      {"factorType": "token:software:totp", "provider": "OKTA"},
      {"factorType": "sms", "provider": "OKTA"},
      {"factorType": "call", "provider": "OKTA"},
      {"factorType": "email", "provider": "OKTA"},
      {"factorType": "question", "provider": "OKTA"},
      {"factorType": "webauthn", "provider": "FIDO"}
    ]
  }
}
```

**Critical insight:** the factor list reveals which factors are available — phishing-resistance varies dramatically:
- `webauthn` (FIDO2) — phishing-resistant
- `question` (security questions) — extremely weak; KBA attacks
- `sms` / `call` — phishing-able (push notification fatigue, SIM swap)
- `push` — phishing-able via MFA fatigue
- `email` — phishing-able if attacker has email read access
- `totp` — phishing-able via AiTM

---

## Password attempts (only if the RoE authorizes them)

Okta's default lockout is often 10 failures, and some orgs set it to 3. You usually cannot read the number from outside. Treat 3 as the planning number.

Do **not** walk a password list. When the RoE explicitly allows credential validation:

- **1** attempt per user, serial, atomic state file. A second attempt only if the RoE names that cap and you still have not locked anyone.
- The only secrets are a client-supplied pair for that user, or one known org default the RoE names.
- Stop on the first valid hit (`MFA_REQUIRED`, `SUCCESS`, `PASSWORD_EXPIRED`) and on any `LOCKED_OUT` / `E0000119` you did not have budget to cause.
- If the RoE does not authorize password attempts, map factors from a flow you are allowed to see and stop. Do not POST a guessed password to real users.

### Authn endpoint (the one RoE-authorized secret, not a list)
```bash
# Same /api/v1/authn — see authentication flow above
```

### Status codes to watch for
| Response | Meaning |
|---|---|
| `200 status=MFA_REQUIRED` | **Password is VALID** — MFA challenge waiting |
| `200 status=SUCCESS + sessionToken` | Full auth (only if MFA not required for this user) |
| `200 status=PASSWORD_EXPIRED` | **Password is VALID** but user must change it |
| `200 status=LOCKED_OUT` | Account locked (pre-existing or our cause) |
| `401 E0000004` | Authentication failed (user doesn't exist OR wrong password — Okta unifies) |
| `401 E0000119` | User is locked |
| `429` | Rate-limit hit |

---

## Push-notification fatigue (MFA bombing)

If a valid password is obtained and `push` factor is available, the classic attack: hammer the push factor until the user accepts out of fatigue.

⚠ **OUT OF SCOPE in most red-team engagements** (counts as social engineering / phishing — e.g. phishing was explicitly OOS for authorized-engagement). Document the vector existence but do not execute without explicit sign-off.

### Detection-only check (does target allow it?)
```bash
# Initiate factor verification
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn/factors/<factor_id>/verify" \
  -H "Content-Type: application/json" \
  -d '{"stateToken":"<from_authn>"}'

# A real test would loop this — DON'T do that without explicit OK
```

---

## OIDC redirect_uri tampering

Okta OIDC apps often have a list of allowed `redirect_uri` values. Misconfigurations:

```bash
# Get the app's authorize endpoint
curl -sk "https://<tenant>.okta.com/.well-known/openid-configuration" | python3 -m json.tool

# Test redirect_uri injection
for ruri in \
    "https://attacker.example.com/" \
    "https://target.com.attacker.com/" \
    "https://target.com@attacker.com/" \
    "https://target.com#@attacker.com/" \
    "https://target.com\\@attacker.com/" \
    "//attacker.com/" \
    "https://target.com/cb?next=https://attacker.com/"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<client>&response_type=code&scope=openid&redirect_uri=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$ruri'))")")
  echo "  $ruri → $code"
done
# Any 302 with the attacker URL in Location header = open redirect → auth-code theft chain
# Proof is one code landing on your redirect, then redeeming it once. A 400 "redirect_uri mismatch" is not a finding.
```

Public clients: repeat the authorize request with `code_challenge` omitted and with `code_challenge_method=plain`. If a code is still issued, redeem it once without the verifier (`hunt-oauth`). A server that requires S256 and rejects the omission is not a finding.

Cross-origin auth (CIC / Auth0-derived, 2024 stuffing surface): if the tenant hosts `/usernamepassword/login` or logs `fcoa`/`scoa`, send **one** request from an unregistered `Origin` with **your** test user. A session from a foreign origin is the finding. Classify the limiter (`hunt-brute-force`); do not stuff.

---

## SAML SP misconfiguration check (per-app)

Each Okta SAML app has its own SP metadata:

```bash
# Iterate known app IDs (find via the org's app list — usually in JS bundles or initial login redirects)
curl -sk "https://<tenant>.okta.com/app/<app_id>/sso/saml/metadata"

# Look for:
#   AuthnRequestsSigned="false"  ← see hunt-saml for XSW
#   WantAssertionsSigned="false" ← assertion-replay possible
#   <NameIDFormat>...emailAddress</NameIDFormat>
```

---

## Okta Admin API (post-cred-compromise)

If a valid cred + MFA-completed token is obtained:

```bash
# Get session token
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -d '{"username":"...","password":"..."}'
# → if SUCCESS, response has sessionToken

# Exchange for API token (admin only)
# Test admin endpoints (all require valid SSWS token):
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/users"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/groups"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/apps"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/logs"      # audit log
# Inbound IdP (Scattered Spider primitive): GET only unless RoE allows a write.
# Proof is this role can create/update an IdP — do not persist a rogue IdP.
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/idps"
```

---

## Okta-specific phishing kits (informational — OOS for non-phishing engagements)

- **EvilProxy** — Okta-aware AiTM kit
- **Modlishka** — generic AiTM
- **Evilginx2** — has Okta phishlets

Document existence; do not deploy without explicit phishing scope.

---

## FastPass / Okta Verify abuse

Okta FastPass is push-based + device-bound. Bypasses:
- Device trust spoofing (requires kit + endpoint compromise — internal-only)
- Push fatigue (see above)
- Phishing redirect to fake FastPass prompt

---

## Common Okta tenant configuration patterns

| Indicator | Configuration |
|---|---|
| `<tenant>.okta.com/api/v1/iam/orgs` returns 401 (not 404) | API IAM endpoints enabled — admin attack surface |
| `customize/sign-in` page reachable anon | Tenant brand customization is public — useful intel |
| Multiple `*.okta.com` SAN certs | Multi-tenant org (less common) |
| `oktapreview.com` subdomain | Preview/sandbox tenant — typically weaker security |

---

## Tooling

- **`OktaTerrify`** (github.com/silverhack/OktaTerrify) — post-compromise Okta device-trust / FastPass enumeration. The only verifiable public Okta-specific offensive tool; no other named, maintained "okta-attacker"/"okta-toolkit" utility is verifiable — build engagement-specific scripts against `/api/v1/*` instead of citing unverified tool names.

---

## Validation

| Claim | Proven | Not proven |
|---|---|---|
| User enum | Known-real vs known-absent identifiers differ in `messages` / `remediation` / Location (one pair). Byte-diff the two bodies | A single 401; `/sessions/me` 404; `/api/v1/authn` `E0000004` |
| Password valid | `MFA_REQUIRED` / `SUCCESS` / `PASSWORD_EXPIRED` from the **one** RoE-authorized secret | `E0000004`; a second pattern you were not authorized to send |
| redirect_uri | Browser lands on **your** host **with** `code`/`token`; you redeem once (`hunt-oauth`) | HTTP 400 `redirect_uri mismatch`; a 302 without the code |
| PKCE skip | Token issued after omitting `code_challenge` / using `plain` | Server requires S256 and rejects the omission |
| Room/app assignment | Low-priv session reads another user's app assignment or group | Public `/app/<id>/sso/saml/metadata` |
| Post-auth admin | `SSWS` or session performs a **read** the role should not have (`/api/v1/users` of another person) | 401 on admin API; holding a user `sessionToken` is not admin |
| Inbound IdP writable | Low-priv role's GET/PUT on identity-provider settings shows create/update allowed — **do not persist** a rogue IdP unless RoE says so | Admin-only 403; documenting Scattered Spider as theory |

Detected ≠ proven. `E0000004` is not "user exists". A 101-equivalent (Okta widget loaded) is not ATO.

## Anti-patterns

- **DO NOT use Entra-style spray pace on Okta** — Okta's anti-automation is tuner-different; rate-limit hits faster. Classify the limiter (`hunt-brute-force`); do not walk a password list.
- **DO NOT POST a dummy password to list factors** — map factors from IDX `identify` / `remediation` (no password). Classic `_embedded.factors` appears only after a correct password (`MFA_REQUIRED`). A dummy POST is a lockout attempt and usually a uniform `E0000004`
- **DO NOT assume MFA-fatigue is in scope** — it's social engineering; explicit OK required
- **DO NOT confuse `*.oktapreview.com` with production** — preview is a non-prod tenant, findings have different severity

---

## Bridge to neighboring skills

- `m365-entra-attack` — sibling skill for the M365 case; identical mental model
- `hunt-oauth` — OIDC redirect_uri tampering, state attack, PKCE bypass
- `hunt-saml` — XSW / signature-stripping for per-app SAML SP
- `hunt-mfa-bypass` — push fatigue, OTP brute, replay
- `mid-engagement-ir-detection` — Okta SOC dashboards are sensitive; expect mitigations during testing

---

## Anti-pattern: Okta user enumeration in 2024+

Several techniques publicly documented through 2022 (e.g., `/api/v1/authn` differential errors) have been hardened. Don't rely on stale knowledge — confirm enumeration vector freshness on each engagement by:
1. Testing 1 known-existing username (e.g. `info@<domain>` if reachable)
2. Testing 1 known-not-existing username
3. Comparing responses byte-by-byte and timing

If responses are identical, the vector is hardened — pivot to OneDrive-equivalent or different approach.

---

## Disclosed cases / CVEs / coordinated-disclosure writeups

These are the canonical public references that justify the techniques in this skill. Cite them in reports when applicable and use them as analog cases when scoping novel Okta attack chains.

### 1. Okta + Sitel/Sykes — LAPSUS$ supply-chain breach (Jan 2022, disclosed Mar 2022)

- Refs: <https://sec.okta.com/articles/2022/03/official-okta-statement-lapsus-claims/>, <https://www.okta.com/blog/company-and-culture/oktas-investigation-of-the-january-2022-compromise/>, <https://thehackernews.com/2022/03/new-report-on-okta-hack-reveals-entire.html>, <https://www.itpro.com/security/cyber-security/367236/leaked-mandiant-report-okta-breach-lapsus-operation>
- Flow: LAPSUS$ compromised a support engineer's workstation at Sitel (third-party support sub-processor, acquired Sykes Enterprises). Via Mimikatz + GitHub-hosted tooling on a thin-client jump host, they reached Okta's internal "SuperUser" support tooling for ~25 minutes on Jan 21 2022. Final scope: 2 customer tenants accessed of 366 originally feared.
- Root cause: Third-party support provider with persistent privileged access to customer tenants, weak segmentation, domain creds stored in spreadsheets, no MFA on the inbound VPN account, delayed reporting (Mandiant report Mar 17, public disclosure Mar 22 only after LAPSUS$ tweeted screenshots).
- Year: 2022. Severity: Critical (industry-shaking — reset the trust model for IdP supply chains).

### 2. Okta Customer Support HAR-file leak (Sep-Oct 2023)

- Refs: <https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/>, <https://blog.cloudflare.com/how-cloudflare-mitigated-yet-another-okta-compromise/>, <https://www.beyondtrust.com/blog/entry/okta-support-unit-breach>, <https://www.bleepingcomputer.com/news/security/okta-breach-134-customers-exposed-in-october-support-system-hack/>
- Flow: Okta support employee logged into a personal Google profile on a corp laptop; Chrome sync exfiltrated saved support-service-account creds to a compromised personal device. Threat actor used those creds to log into the support case-management portal Sep 28 - Oct 17 2023, downloaded HAR files that customers had uploaded for troubleshooting. HAR files contained live session cookies/tokens → session-replay against the customers' Okta tenants. 134 customers exposed, 5 had sessions hijacked (BeyondTrust, Cloudflare, 1Password publicly disclosed).
- Root cause: Service-account creds reaching an unmanaged personal device via Chrome profile sync + HAR files containing un-sanitized session tokens accepted for replay (no IP/device binding on support tokens).
- Year: 2023. Severity: Critical. BeyondTrust detected and reported to Okta on Oct 2 2023; Okta did not publicly acknowledge until Oct 19 2023.

### 3. Scattered Spider / Octo Tempest / UNC3944 — Okta tenant social-engineering campaign (2022-2024, ongoing)

- Refs: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a>, <https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection/>, <https://www.darkreading.com/cyberattacks-data-breaches/how-the-okta-cross-tenant-impersonation-attacks-succeeded>, <https://attack.mitre.org/groups/G1015/>
- Flow: Group calls IT help desk impersonating an employee (LinkedIn-profile-sourced identity), requests MFA reset + password reset, gains initial Okta foothold. Then elevates to Okta Super-Admin, configures a second IdP under attacker control, enables inbound federation + account-linking, modifies NameID on attacker-IdP to match the target user, and impersonates any Okta user across the tenant without their cred. Used in MGM and Caesars attacks (Sep 2023, $100M+ losses) and confirmed on 4+ Okta customers in the Jul-Aug 2023 campaign.
- Root cause: Help-desk-as-trust-anchor with no out-of-band verification + Okta inbound federation feature allowing attacker-controlled IdP to issue arbitrary-NameID assertions accepted as authentic.
- Year: 2023 onwards. Severity: Critical. Joint CISA/FBI advisory AA23-320A.

### 4. Okta cross-origin authentication credential stuffing (Apr-May 2024)

- Refs: <https://sec.okta.com/articles/2024/05/detecting-cross-origin-authentication-credential-stuffing-attacks/>, <https://thehackernews.com/2024/05/okta-warns-of-credential-stuffing.html>, <https://arcticwolf.com/resources/blog/okta-cross-origin-authentication-feature-customer-identity-cloud-targeted-credential-stuffing-attacks/>
- Flow: Customer Identity Cloud (Auth0-derived) cross-origin auth endpoint silently accepted credential-stuffing from unregistered origins. Observed Apr 15 - May 2024. Tenant log signals: `fcoa` (failed cross-origin auth), `scoa` (successful cross-origin auth), `pwd_leak` (breached password match).
- Root cause: Cross-origin auth permitted on all tenants by default with no origin allowlist enforced at the auth-API edge; credential-stuffing throttling applied per-endpoint not per-tenant.
- Year: 2024. Severity: High (mass-scale ATO via reused creds).

### 5. Okta AD/LDAP DelAuth bcrypt cache-key auth bypass (Oct 2024) — no CVE

This is **not** CVE-2024-0981. That CVE is reflected XSS in the Okta Browser Plugin 6.5.0–6.31.0 (fixed 6.32.0) and has nothing to do with DelAuth. The cache-key bug was not issued a CVE. Cite the advisory, not a CVE number.

- Refs: <https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/>, <https://www.theregister.com/2024/11/04/why_the_long_name_okta/>, <https://www.nodejs-security.com/blog/okta-bcrypt-security-incident-bun-nodejs>
- Flow: Okta cached AD/LDAP DelAuth results keyed by `bcrypt(userId + username + password)`. Bcrypt silently truncates input at 72 bytes. When username length ≥ 52 chars, the password bytes fall past the 72-byte boundary → cache key collapses to be password-independent. If the user had a prior successful login (cache populated) AND the AD/LDAP agent was unreachable AND MFA was disabled → any password authenticated.
- Root cause: Using bcrypt as a general-purpose hash without accounting for the algorithm's 72-byte input limit + cache fallback path inverted the security model (cache trusted over live auth).
- Year: 2024. Severity: High. Bug introduced Jul 23 2024, internally found and fixed Oct 30 2024 (~3 months exposure window).

### 6. Okta Verify iOS push-response bypass (CVE-2024-10327, disclosed Oct 2024)

- Refs: <https://trust.okta.com/security-advisories/okta-verify-for-ios-cve-2024-10327/>
- Flow: Okta Verify iOS 9.25.1-beta / 9.27.0 had a bug in the iOS ContextExtension push-action handler. From the lock screen long-press / drag-down banner / Apple Watch reply path, both the "Yes, it's me" and "No, it's not me" buttons returned the same accept-auth response. A push-fatigued user who explicitly tapped "No" still approved the auth.
- Root cause: Two notification-response action handlers wired to the same backend confirmation path — UX-level Deny did not propagate as a backend rejection.
- Year: 2024. Severity: High (silently defeats the user's last line of defence against push fatigue / Scattered-Spider-style push bombing).

### 7. Varonis Threat Labs — "CrossTalk" + "Secret Agent" Okta abuse (Jan 2023)

- Refs: <https://www.varonis.com/blog/okta-attack-vectors>
- Flow: (a) CrossTalk: any Okta tenant admin (incl. free-developer tenant) could issue SMS / email templates that delivered to *any* email/phone — sent via legitimate Okta mailer infrastructure (passes SPF/DKIM/DMARC for okta.com). Used to stage cross-tenant phishing that arrives from a trusted sender. (b) Secret Agent: the SSWS token stored on the on-prem Okta AD-agent sync server was decryptable from disk; possessor could register a rogue AD agent that intercepted DelAuth plaintext credentials for the entire org.
- Root cause: (a) Tenant-bounded sender identity not enforced on outbound notification API. (b) Agent SSWS bootstrap-secret stored recoverable on disk; new-agent enrollment did not require admin co-signature.
- Year: 2023. Severity: High for both. Disclosed and patched by Okta.

### 8. Okta admin-console session cookie theft via stealer malware (2022-2024, ongoing class)

- Refs: <https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection/>, <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a>, <https://www.beyondtrust.com/blog/entry/okta-support-unit-breach>
- Flow: Class of attack — stealer malware (Lumma, RedLine, Raccoon, StealC) on a corp endpoint exfiltrates `sid` cookie from `<tenant>.okta.com` and `<tenant>-admin.okta.com`. Without IP-binding or device-binding on the Okta session, the attacker replays the cookie from a residential proxy and obtains the user's full session (incl. admin if the victim was an admin) — bypasses MFA entirely (already-MFA-completed session). Underpinned both the Oct 2023 HAR-file incident and most Scattered Spider intrusions.
- Root cause: Okta session cookies (until DPoP / Device Bound Session Cookies / asymmetric session keys are enforced) are bearer tokens — anyone holding the cookie is the user.
- Year: 2022-2024 (ongoing class). Severity: Critical when admin sessions stolen.

### Take-aways for hunters

- The 2022 LAPSUS$, 2023 HAR-file, and 2023 Scattered Spider campaigns share a pattern: **the attack rarely hits Okta's product code — it hits the trust relationships around Okta** (third-party support, help-desk verification, customer-uploaded artifacts, federated IdPs). Recon should map these trust edges first.
- The DelAuth bcrypt truncation (advisory only — **not** CVE-2024-0981) was a rare product bug and it was fixed on 2024-10-30. CVE-2024-0981 is the browser-plugin XSS. Most disclosed Okta incidents are configuration or operational, not a live product CVE to replay.
- Push fatigue stays social engineering and needs explicit sign-off. CVE-2024-10327 is narrower than "every push is bypassable": Okta Verify for iOS 9.25.1-beta and 9.27.0 only, ContextExtension reply path (lock-screen long-press, drag-down banner, Apple Watch), and the user had to have enrolled under Okta Classic. Do not file "push is bypassable" without those conditions and a demonstrated wrong-button accept. The DelAuth cache-key bug was fixed in Okta production on 2024-10-30; do not probe it on a live tenant in 2026. Log review for that window is the client's, if the RoE includes it.
- For red-team scoping: HAR-file replay, inbound-federation IdP injection, and stealer-cookie replay are the three highest-yield post-recon primitives observed in the wild.

---

## Related Skills & Chains

- **`hunt-subdomain`** — Okta tenant naming patterns (`<org>.okta.com`, `<org>.oktapreview.com`, `<org>-admin.okta.com`) frequently include orphan/dev tenants. Chain primitive: Okta tenant discovery via `/.well-known/okta-organization` → enumerate `<org>-dev`, `<org>-uat`, `<org>-test` subdomains → `hunt-subdomain` orphan-tenant identification → claim abandoned tenant → SSO takeover (legitimate `<org>` users redirected through compromised IdP for any app federated to the dev tenant).
- **`m365-entra-attack`** — Okta-as-IdP for M365 is common in hybrid orgs. Chain primitive: a session or RoE-validated Okta user that is federated to Entra receives a SAML assertion → M365 access without a separate password guess at `login.microsoftonline.com`. Enumeration alone is not that chain.
- **`hunt-saml`** — Okta issues SAML assertions to every federated downstream app. Chain primitive: Okta admin or developer credential captured → mint arbitrary SAML assertions in Okta admin → `hunt-saml` XSW or signature manipulation not even needed — legitimately signed assertions for arbitrary impersonation across every federated app (Salesforce, Workday, AWS, GitHub, M365).
- **`hunt-mfa-bypass`** — After a legitimate `MFA_REQUIRED`, test factor logic (step skip, response confusion) per that skill. Push bombing and SIM-swap are out of scope unless the RoE explicitly allows them. CVE-2024-10327 is a version-specific iOS bug, not a default test.
- **`triage-validation`** — Okta findings can be high-impact but need the 7-Question Gate run on whether the captured artifact (token, code, factor) actually grants meaningful access. Chain primitive: validated Okta primitive → `triage-validation` to confirm access plane → `redteam-report-template` with explicit federated-app blast-radius.
