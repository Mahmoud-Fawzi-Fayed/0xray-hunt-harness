---
name: hunt-desktop-macos
description: Hunt macOS desktop application vulnerabilities — Electron abuse, custom URL-scheme argument injection (CFBundleURLTypes), XPC / privileged-helper attacks (SMJobBless, audit-token vs PID validation), dylib hijacking (@rpath ordering, DYLD_INSERT_LIBRARIES, disable-library-validation), Sparkle updater MITM (HTTP SUFeedURL, missing SUPublicEDKey), entitlement / hardened-runtime misconfig (get-task-allow, allow-dyld-environment-variables), TCC grant theft via injection, localhost servers + DNS rebinding, AppleEvent/AppleScript injection, embedded secrets (Info.plist, UserDefaults, Keychain), DMG/pkg installer analysis. Use when the target is a macOS app (.app/.dmg/.pkg), an Electron build, a menu-bar agent, or a desktop app with a companion web portal.
sources: authorized-engagement
---

## Crown Jewel Targets

Same economics as Windows desktop: the trigger must be **remote** (deep link, drive-by on a localhost server, MITM of the updater) or the asset must be high-value (Keychain material, signing keys, SSO tokens, TCC-protected data). Local root privesc via XPC is a red-team staple but is frequently out of scope in web BB programs — chain to a remote trigger or check the brief.

**Highest-value targets:**

- **Apps with privileged helpers** (`/Library/PrivilegedHelperTools`, `SMJobBless`/`SMAppService`) — unauthenticated XPC = root
- **Sparkle-updated apps** — `SUFeedURL` over HTTP or missing `SUPublicEDKey` = MITM RCE across the whole install base
- **Electron apps** (collab, wallets, trading) — isolation misconfig + XSS = RCE; deep links that move funds
- **VPN / zero-trust / EDR agents** — root daemons, network extension entitlements, SSO token custody
- **Menu-bar / "helper" utilities** — ship XPC services and broad entitlements with minimal review
- **Apps holding TCC grants** (Full Disk Access, Accessibility, Screen Recording) — injection into the process inherits the grant

**Asset types that pay most:** one-click RCE from browser (URL scheme / Electron XSS) > MITM update RCE > root privesc via XPC (scope-dependent) > TCC grant theft > Keychain/token disclosure.

---

## Attack Surface Signals

**Bundle signals:**
```
Contents/Info.plist
  CFBundleURLTypes               → custom URL schemes (deep-link entry)
  SUFeedURL / SUPublicEDKey      → Sparkle updater; HTTP feed or missing key = finding
  NSAppleEventsUsageDescription  → AppleEvents to other apps (automation surface)
  LSUIElement / LSBackgroundOnly → agent app; often has a daemon sibling
Contents/XPCServices/*.xpc       → app-private XPC services (audit each)
Contents/Library/LaunchServices  → bundled login items / helpers
Contents/Frameworks/*.dylib      → @rpath candidates; note install_name
Contents/_CodeSignature          → entitlements live here (codesign -dv)
```

**Entitlement red flags (`codesign -dv --entitlements :- /Applications/App.app`):**
```
com.apple.security.cs.get-task-allow                  → debuggable release build: Frida/lldb attach, runtime patch
com.apple.security.cs.disable-library-validation      → loads unsigned dylibs → plant/inject
com.apple.security.cs.allow-dyld-environment-variables → DYLD_INSERT_LIBRARIES works
com.apple.security.cs.disable-executable-page-protection → RWX pages; exploit dev made easier
com.apple.security.automation.apple-events            → can AppleScript other apps (check which)
com.apple.security.network.server                     → listens; find the listener
com.apple.security.temporary-exception.*              → legacy sandbox escape hatches; read each one
```

**System-level surface:**
```
/Library/PrivilegedHelperTools/*  → root helpers; match to LaunchDaemons plist
/Library/LaunchDaemons/*.plist    → MachServices key names the XPC listener
/Library/LaunchAgents/*           → user-context agents
launchctl print system/<label>    → live daemon state, PID, entitlement requirements
lsof -iTCP -sTCP:LISTEN -P        → localhost/0.0.0.0 listeners before vs after launch
```

---

## Step-by-Step Hunting Methodology

1. **Acquire and unpack the exact build.** `.dmg` → `hdiutil attach`; `.pkg` → `pkgutil --expand-full app.pkg out/` (read `Payload`, `Scripts` — pre/postinstall scripts run as root and are a finding class on their own). Record version, Team ID, SHA256. Check notarization: `spctl -a -vv App.app`, `stapler validate App.app` — notarization ≠ secure, but its absence on a distributed app is itself reportable context.

2. **Entitlement + hardened-runtime audit.** `codesign -dv --entitlements :- App.app`. Map every entitlement to its attack primitive (table above). `get-task-allow` in a release build means attach-and-patch with Frida/lldb without disabling SIP — treat as a confirmed finding, then look for what it unlocks (token extraction from memory, pinning bypass).

3. **Electron audit.** Identical class to the Windows skill: extract `Contents/Resources/app.asar`, grep `webPreferences`, audit preload bridges and `ipcMain` sinks, check `setAsDefaultProtocolClient` + `open-url` handling. macOS-specific: deep links arrive via the `open-url` event — check whether the handler validates the URL before acting (fund transfers, account linking, file opens). **Electron Fuses** (2024-2026): dump with `npx @electron/fuses read --app /Applications/App.app` — `RunAsNode` enabled + `ELECTRON_RUN_AS_NODE=1` = arbitrary Node exec in the app's TCC/entitlement context (a code-injection + TCC-grant-theft primitive on its own); `EnableNodeCliInspectArguments` on = attach a debugger via `--inspect`; `EnableEmbeddedAsarIntegrityValidation` / `OnlyLoadAppFromAsar` off = plant a modified ASAR. Each off-fuse is a concrete finding when it unlocks reachable impact.

4. **URL-scheme audit.** For each `CFBundleURLTypes` entry, find the handler (`application:openURL:` / `onOpenURL` / Electron `open-url`). On macOS the OS delivers the URL via Apple Event / `open-url` — it is **not** Chromium argv (the Windows `--gpu-launcher` break). Primary tests: the URL string reaches `osascript` / `NSTask` / `Process` with interpolation, a fund-move / file-open action with no confirm, or a second-order fetch. Try argv injection once anyway (some wrappers forward the URL on `process.argv`); failure there is not "no scheme bug". Drive from a browser PoC page — Safari navigates custom schemes with one prompt.

5. **XPC / privileged-helper audit (highest privesc yield).**
   - Enumerate: `launchctl list`, `launchctl print system/<label>`, read the LaunchDaemon plist's `MachServices`.
   - Connect to the named Mach service as a standard user (pyobjc / xpcspy). If the connection succeeds, the helper's client-validation is the whole game.
   - Classify validation: **none** → root command execution, report; **PID-based** (`processIdentifier`) → racy, exploitable via PID reuse/spawn race; **audit-token-based** (`auditToken`, e.g. `SMJobBless` code-requirement check) → solid unless the requirement string is broken (anchor-generic, missing `identifier`, `info`/`certificate` confusion).
   - Audit the exposed protocol methods for: file write/move/delete as root, `NSTask`/`Process` launch with caller-controlled path or args, package install, "update" verbs, and path traversal in caller-supplied paths (symlink races in `/tmp`, `NSTemporaryDirectory`).

6. **Dylib hijacking.** `otool -l App.app/Contents/MacOS/App | grep -A3 LC_RPATH` and `otool -L` for `@rpath` imports. Hijackable when: an `LC_RPATH` entry points to a writable/missing location searched **before** the real one, or the app has `disable-library-validation` + a writable `Contents/Frameworks`. Objective-See's Dylib Hijack Scanner automates the sweep. Impact: code exec inside the app's TCC/entitlement context.

7. **Sparkle updater.** Read `SUFeedURL` and `SUPublicEDKey` / `SUPublicDSAKey` (Sparkle 1). HTTP is MITM of the *feed*, not automatic RCE: with **no** public key, a MITM appcast+archive installs (RCE). **With** a public key, Sparkle still requires a valid EdDSA/DSA signature — claim rollback to an older *signed* build, or `defaults write` feed override if honored, not "unsigned item accepted because HTTP". Tests: spoof via `hosts`/proxy; serve a valid-signature older version; delta path traversal.

8. **Localhost servers + WebSocket bridges.** `lsof -iTCP -sTCP:LISTEN -P` before/after launch and sign-in. Same gates as Windows: bind address, Host-header validation (DNS rebinding), WebSocket `Origin` check, auth model. macOS flavor: many apps bridge browser→app via `ws://127.0.0.1` with a token in the URL — check whether the token is guessable, logged (`log show`), or leaked via `ps`.

9. **Secrets.** `Info.plist` (hardcoded keys), `*.strings`, `defaults read <bundle-id>` (tokens in UserDefaults), Keychain (`security find-generic-password -s <service>` — note access group and `kSecAttrAccessible`), `log show --predicate 'process == "App"' --last 1h` (tokens in unified logs), embedded PEMs in the binary (`strings`, Hopper). ObjC/Swift symbols: `class-dump`, `swift-demangle` — internal endpoints and feature flags fall out.

10. **AppleEvents / automation.** If the app holds `com.apple.security.automation.apple-events` or an `NSAppleEventsUsageDescription`, check what it can drive (Mail, Safari, Finder = data theft / code exec chains) and whether it builds AppleScript/`osascript` commands via string interpolation from deep-link or IPC input.

---

## Payload & Detection Patterns

**Unpack + entitlement triage:**
```bash
hdiutil attach App.dmg && cp -R /Volumes/App/App.app /tmp/
pkgutil --expand-full App.pkg out/          # .pkg path; read out/Scripts as root-run code
codesign -dv --entitlements :- /tmp/App.app 2>&1
codesign -dvvv /tmp/App.app 2>&1 | grep -E 'TeamIdentifier|Authority'
spctl -a -vv /tmp/App.app; stapler validate /tmp/App.app
```

**XPC service discovery + client probe:**
```bash
grep -A5 MachServices /Library/LaunchDaemons/com.vendor.helper.plist
launchctl print system/com.vendor.helper
```
```python
# pyobjc probe: connect as a standard user. LaunchDaemon helpers usually need the
# privileged option; 0 alone often invalidates and looks like "not vulnerable".
import objc
from Foundation import NSXPCConnection
NSXPCConnectionPrivileged = 1 << 12
name = "com.vendor.helper"
for opts in (0, NSXPCConnectionPrivileged):
    c = NSXPCConnection.alloc().initWithMachServiceName_options_(name, opts)
    c.setInvalidationHandler_(lambda opts=opts: print(f"INVALIDATED opts={opts}"))
    c.resume()
# Set the remote interface from class-dump before calling a method.
# Accepted connection is not root. A method you invoked that writes or execs as root is the proof.
```

**Dylib-hijack sweep:**
```bash
otool -l App.app/Contents/MacOS/App | grep -A3 LC_RPATH
otool -L App.app/Contents/MacOS/App | grep '@rpath'
# candidate: first LC_RPATH entry → dir that is missing or user-writable
# confirm: plant a dylib exporting the missing symbol, relaunch, observe load
```

**Sparkle feed triage:**
```bash
/usr/libexec/PlistBuddy -c 'Print :SUFeedURL' App.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c 'Print :SUPublicEDKey' App.app/Contents/Info.plist 2>&1
/usr/libexec/PlistBuddy -c 'Print :SUPublicDSAKey' App.app/Contents/Info.plist 2>&1
# HTTP + no key → MITM RCE; HTTP + key → rollback of a signed build, not a forged archive
defaults read <bundle-id> SUFeedURL 2>/dev/null   # user-overridable feed?
```

**URL-scheme injection probe:**
```bash
# Primary (macOS): Apple Event / open-url. Interpolation and unconfirmed actions.
open 'targetscheme://action?path=$(touch /tmp/pwned-UNIQ)'
open 'targetscheme://send?to=attacker&amount=1'
# Secondary: some wrappers still forward the URL on argv — try once, ignore if it no-ops
open 'targetscheme://x" --gpu-launcher="open -a Calculator'
```

**Runtime attach when `get-task-allow` is present:**
```bash
frida -n App -l bypass-pinning.js        # no SIP change needed on entitled builds
lldb -n App -o 'br s -n SecItemCopyMatching' -o c
```

**Localhost API rebinding gate:**
```bash
curl -s http://127.0.0.1:PORT/api/status -H 'Host: attacker.example' -w '\n%{http_code}\n'
```

---

## Common Root Causes

1. **XPC helper with no or PID-only client validation.** Root daemon exposes file/process verbs to any local process; PID checks lose to spawn races. The canonical macOS privesc class.

2. **Sparkle misconfig: HTTP `SUFeedURL` with no `SUPublicEDKey`/`SUPublicDSAKey`.** MITM serves a malicious appcast+archive → silent replacement. HTTP **with** a public key is not arbitrary RCE (signature still required) — rollback of a signed-but-vulnerable build, or a `defaults write` feed override, is the remaining path.

3. **URL-scheme handlers that trust input.** Deep link reaches `NSTask`/`osascript`/file-write without validation; browser navigation is the remote trigger. On macOS the URL arrives via `open-url` / Apple Event — do not require a Chromium argv break to call it a bug.

4. **`disable-library-validation` + writable `Contents/Frameworks`.** Plant a dylib → code exec in the app's entitlement/TCC context (inherits Full Disk Access, Screen Recording, etc.).

5. **`get-task-allow` shipped in release.** Anyone can Frida/lldb the process: extract tokens from memory, patch pinning, call internal methods.

6. **Localhost bridge without Host/Origin validation.** "localhost = trusted" assumption; DNS rebinding / CSWSH turns any web page into a client of the local API.

7. **Tokens in UserDefaults / unified logs / world-readable files.** `defaults write` stores session tokens in plaintext plist; `NSLog`/`os_log` ships them to `log show`.

8. **Root-run installer scripts.** `.pkg` pre/postinstall with unquoted paths, writable temp files, or curl|sh update logic — root code exec at install time.

9. **Symlink/temp-file races in privileged helpers.** Helper writes to caller-supplied or predictable `/tmp` paths → symlink → arbitrary root file write.

10. **Electron isolation misconfig** — identical root causes as the Windows skill; macOS adds the `open-url` handler as an extra unvalidated entry point.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| Hardened runtime | It only blocks what the entitlements block — enumerate `com.apple.security.cs.*` exceptions first; most apps ship at least one escape hatch |
| Library validation (no foreign dylibs) | `disable-library-validation` present → plant; absent → check `LC_RPATH` ordering hijack with a re-exporting dylib (same-team load is allowed) |
| Audit-token XPC validation | Check the code-requirement string: `anchor apple generic` without `identifier` = any Apple-signed binary qualifies; look for sibling interfaces (Distributed Objects, raw Mach bootstrap ports, socket-based XPC) with no check |
| PID-based XPC check | Win the spawn race: fork/exec loop reusing the PID, or `posix_spawn` with the right attrs; document the race window in the report |
| Signed Sparkle updates | Rollback to a signed-but-vulnerable version; delta-update path traversal; `SUFeedURL` override via `defaults write` or MDM profile |
| SIP (can't touch system paths) | Target user-writable `~/Library` paths, the app bundle itself (often user-owned when self-updated), and `/tmp` races in helpers |
| Keychain ACL on tokens | Read the access group: shared groups (`apple`/`team` generic) let other same-team apps read; `kSecAttrAccessibleAlways` legacy items readable when unlocked; check for a plaintext mirror in UserDefaults |
| Notarization / Gatekeeper | Not a defense-in-depth control — it gates install, not runtime behavior; note it and move on |
| TCC prompt on protected dirs | Don't fight the prompt — inherit the grant by injecting into an app that already holds it (dylib hijack / `get-task-allow` attach) |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What is the remote trigger?** Rank: browser deep link → RCE (Critical) > MITM update (High-Critical, needs network position) > rebinding/CSWSH drive-by on the local bridge (High) > XPC root privesc (High on red team; often out of scope in BB — check the brief) > TCC/token theft (needs an injection primitive to matter).

2. **Have you reproduced on a clean VM?** Record macOS version, arch (arm64 vs x86_64 — dylib payloads must match), app version + Team ID + SHA256. If the PoC needs SIP disabled or non-default settings, severity drops — say so explicitly.

3. **Can a triager reproduce in <10 min?** Provide: the exact `.dmg`/`.pkg` version, the PoC page (deep link / rebinding), copy-pasteable `open`/`curl`/pyobjc commands, and expected vs actual result. For XPC, include the LaunchDaemon plist `MachServices` name and the vulnerable protocol method.

4. **Cross-reference `triage-validation`.** "XPC connects" / "feed is HTTP" / "entitlement present" are primitives, not impact — the chain must terminate in attacker-attainable effect before claiming the severity.

---

## Real Impact Examples

### Scenario A — Meeting-app privileged helper with no XPC client validation → root

`/Library/LaunchDaemons/com.vendor.helper.plist` exposes `MachServices: com.vendor.helper`. A standard-user pyobjc client connects unchallenged; the protocol exposes `installPackageAtPath:` which runs `installer` as root on a caller-controlled path. Dropped `.pkg` → root. Reported severity: **High** (local privesc; program scope confirmed local privesc in-bounds).

### Scenario B — Sparkle HTTP feed with no public key → MITM RCE

Info.plist: `SUFeedURL = http://updates.vendor.example/appcast.xml`, **no** `SUPublicEDKey` / `SUPublicDSAKey`. Hostile network serves a malicious appcast + archive; Sparkle installs it at the next check. If a public key **is** present, an unsigned `<item>` is rejected — then prove rollback of an older signed build, or that `defaults write <bundle> SUFeedURL` is honored, before claiming RCE. Reported severity: **High** (network position).

### Scenario C — Electron wallet: `open-url` handler without confirmation → fund theft

`CFBundleURLTypes` registers `wallet://`. The `open-url` handler parses `wallet://send?to=<addr>&amount=<n>` and signs the transaction without a confirmation dialog when a session is unlocked. Browser PoC page navigates the scheme once. Reported severity: **Critical** (direct financial impact, one-click).

### Scenario D — `get-task-allow` on a release VPN client → SSO token theft

Release build ships `com.apple.security.cs.get-task-allow`. `frida -n VPNClient` attaches without SIP changes; a 20-line script reads the SSO refresh token from a static ObjC property. Combined with the token's broad Entra scope, this is account takeover from any local process. Reported severity: **High**.

---

## Related Skills & Chains

- **`hunt-desktop-windows`** — Sibling skill; Electron isolation, preload-bridge, updater, and deep-link classes transfer directly. Chain primitive: same vendor ships both builds → a confirmed misconfig in one is near-certain in the other; check both before reporting either.
- **`hunt-xss`** — Renderer XSS is the entry primitive for Electron RCE. Chain primitive: stored/reflected XSS + `contextIsolation: false` or over-exposed preload → `require('child_process')` → `hunt-rce`.
- **`hunt-websocket`** — Localhost `ws://` bridges without `Origin` checks = CSWSH against the desktop client. Chain primitive: `lsof` shows a `127.0.0.1` WS listener + no Origin validation → browser page drives the app.
- **`hunt-cors`** / **`hunt-host-header`** — Localhost HTTP bridges fail Host/Origin validation exactly like web CORS bugs. Chain primitive: permissive `Access-Control-Allow-Origin` on the local API → direct cross-origin `fetch`, no rebinding needed.
- **`hunt-source-leak`** — Extracted ASAR / `class-dump` output / Info.plist is a source leak: mine endpoints, keys, feature flags, then pivot to the web hunt-* set against the companion API.
- **`m365-entra-attack`** / **`okta-attack`** — Tokens recovered from Keychain/UserDefaults/memory feed identity-platform chains. Chain primitive: SSO refresh token on disk → `m365-entra-attack` token-replay flow.
- **`triage-validation`** — Run the 7-Question Gate before submission; macOS findings inflate easily ("entitlement present" ≠ exploitable) and bounce without a full chain.
- **`evidence-hygiene`** / **`report-writing`** — Token and Keychain PoCs leak real credential material; redact per evidence-hygiene, format per report-writing.
