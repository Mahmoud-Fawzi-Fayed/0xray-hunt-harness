---
name: hunt-ntlm-info
description: "Hunt NTLM/Negotiate information disclosure on internet-reachable IIS/SharePoint/Exchange. Anonymous NTLM Type-2 challenge capture leaks NetBIOS domain, internal DNS forest, computer name, AD timestamp via AV_PAIRS structure. Default Windows-installer hostnames (WIN-XXXXXXXXXXX pattern) signal lazy provisioning. Use when target advertises `WWW-Authenticate: NTLM` or `Negotiate` headers anonymously."
sources: github, authorized-engagement
report_count: 1
---

# HUNT-NTLM-INFO — Anonymous NTLM Type-2 disclosure

One unauthenticated Type-1 message. The Type-2 challenge's AV_PAIRS name the computer, the domain, and the forest. That is the whole bug. It is not an authentication bypass, and it is not a license to spray, crack, or forge tickets.

## Rails
- In-scope hosts only. One probe per endpoint.
- No password spraying, credential stuffing, NTLM relay against other hosts, hash cracking, or golden-ticket forging.
- The server challenge bytes are not an invitation to crack a hash you do not have.
- A `WIN-` hostname is a naming smell. It is not evidence of a default password.
- Stop at draft. Never auto-submit. Claim only the strings you decoded.

## Decision tree

1. **Offer.** `GET` the URL. `WWW-Authenticate: NTLM` or `Negotiate` on an anonymous response means continue. Paths that often do this on IIS, SharePoint, Exchange, ADFS, RD Web, WSUS: `/_api/web/CurrentUser`, `/_vti_bin/`, `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/owa/`, `/Microsoft-Server-ActiveSync`, `/rpc/rpcproxy.dll`, `/RDWeb/`, `/certsrv/`, `/PowerShell`. Any in-scope URL that sends the header is enough — do not scrape a wordlist.
2. **Type-1.** Send the negotiate message below on a **keep-alive** HTTP/1.1 connection. Many stacks put the Type-2 in the `401` to this same request; some close the socket first. If curl shows only the scheme name, repeat with a raw socket or Burp Repeater (`Connection: keep-alive`).
3. **Decode AV_PAIRS** from `WWW-Authenticate: NTLM <base64>`. If the blob does not start with `NTLMSSP\0` and message type 2, it is not a capture.
4. **Write down** NetBIOS computer, NetBIOS domain, DNS computer, DNS domain, DNS tree, and timestamp. Those strings are the finding.
5. **Severity from what is on the wire,** not from a guessed follow-up. Internet-reachable internal FQDN is information disclosure (often Medium when the program accepts topology leaks, otherwise Low). A hostname with no domain, or a host that is outside the engagement, is not a report. Do not upgrade it because spraying "would" work.

Type-1 (flags ask for Unicode target info; version field is a Win7-era client the responders accept):
```
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
```

AV_PAIR ids: `1` computer (NetBIOS), `2` domain (NetBIOS), `3` DNS computer, `4` DNS domain, `5` DNS forest, `7` FILETIME, `9` target name.

## Capture

```bash
curl -sk --http1.1 -D - -o /dev/null \
  -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  "https://TARGET/PATH" | tr -d '\r' | grep -i "^WWW-Authenticate:"
```

```python
import socket, ssl, base64, struct, re
from datetime import datetime, timezone

HOST, PATH = "TARGET", "/PATH"
ctx = ssl.create_default_context()
s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
s.sendall(
    f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\n"
    "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n"
    "Connection: close\r\n\r\n".encode()
)
data = b"".join(iter(lambda: s.recv(8192), b""))
m = re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{20,})", data, re.I)
b = base64.b64decode(m.group(1))
assert b[:8] == b"NTLMSSP\x00" and b[8] == 2
tn_len, _, tn_off = struct.unpack_from("<HHI", b, 12)
ti_len, _, ti_off = struct.unpack_from("<HHI", b, 40)
names = {1: "NetBIOS computer", 2: "NetBIOS domain", 3: "DNS computer",
         4: "DNS domain", 5: "DNS tree", 7: "Timestamp", 9: "Target name"}
print("TargetName", b[tn_off:tn_off + tn_len].decode("utf-16-le", "replace"))
i, ti = 0, b[ti_off:ti_off + ti_len]
while i + 4 <= len(ti):
    av_id, av_len = struct.unpack_from("<HH", ti, i)
    if av_id == 0:
        break
    val = ti[i + 4:i + 4 + av_len]
    if av_id == 7 and len(val) >= 8:
        ticks = struct.unpack("<Q", val[:8])[0]
        shown = datetime.fromtimestamp((ticks - 116444736000000000) / 1e7, timezone.utc).isoformat()
    else:
        shown = val.decode("utf-16-le", "replace")
    print(f"AV[{av_id}] {names.get(av_id, '?'):20} {shown}")
    i += 4 + av_len
```

No Collaborator. The disclosure is in this response. The 8-byte server challenge in the Type-2 is not a password hash.

## Validation
- Quote the decoded AV strings and the URL that returned them. A second request should return the same names.
- Do not claim: default passwords, a crackable hash, a trust path you did not authenticate across, "Critical with brute force", or impact on a host that did not answer.
- Negotiating NTLM on an internal-only name the program did not list is out of scope, not a low finding to file anyway.
- Extended Protection / "NTLM stripped at the proxy" is defender context. If the Type-2 still arrives anonymously, the leak exists.

## Chains
Use the names as **recon in the report**, not as a wordlist.
- SharePoint/Exchange on the same host → `hunt-sharepoint` / `hunt-aspnet` for a separate, proven bug. The forest name does not make that bug worse by itself.
- DNS tree matches an in-scope Entra tenant (`login.microsoftonline.com/<domain>/.well-known/openid-configuration`). Identifying the tenant is OSINT. Username enumeration and spraying stay forbidden.
- `hunt-auth-bypass` only if that skill independently shows a missing check. Do not add a spray endpoint to the narrative.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
