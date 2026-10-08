---
name: hunt-source-leak
description: Hunt source code and build artifact leakage — JavaScript source maps (.js.map) reconstructing TypeScript/ES6 source, Swagger/OpenAPI JSON endpoint discovery, .env/.git exposure, webpack chunks with hardcoded secrets, robots.txt/security.txt recon, build-info files, asset-manifest.json API route discovery, .DS_Store file listing. Use at the START of every recon session — these findings often unlock the entire attack surface.
sources: hackerone_public, offensive_research
report_count: 31
---

# HUNT-SOURCE-LEAK — Source code & build artifact leakage

A `200` is not a leak. SPAs return the same `index.html` for every unknown path. Compare the candidate to a random path before you call it.

## Decision tree

1. Fetch a baseline: `https://$TARGET/zz-no-such-<rand>`. Save status, length, and the first bytes.
2. Fetch the candidate. **Same body as baseline → SPA fallback. Drop it.**
3. Confirm the content type: `.env` looks like `KEY=value`, `.git/HEAD` is `ref: refs/heads/…`, OpenAPI contains `"openapi"` or `"swagger"`, a source map contains `"sourcesContent"`.
4. If it is a secret, prove it is **live and in-scope** with one read-only call. A placeholder (`changeme`, `example`, `AKIA` + `EXAMPLE`) is not a finding.
5. Pivot into the skill that consumes the artifact (routes → `hunt-api-owasp`, keys → the service they open, DOM sinks → `hunt-dom`).

## High-value paths

Probe this set (targeted names, not a giant brute). Record hits that differ from the baseline.

```text
/.env  /.env.local  /.env.production  /.env.bak  /.env.old
/.git/HEAD  /.git/config  /.svn/entries  /.hg/requires
/swagger.json  /v3/api-docs  /openapi.json  /api/openapi.json  /swagger/v1/swagger.json
/api-docs  /graphql  /graphiql
/actuator/env  /actuator/heapdump  /actuator/mappings
/serverless.yml  /terraform.tfstate  /appsettings.json  /local.settings.json  /web.config
/package.json  /composer.json  /composer.lock  /Gemfile
/asset-manifest.json  /manifest.json  /_next/static/<buildId>/_buildManifest.js
/robots.txt  /.well-known/security.txt  /sitemap.xml
/phpinfo.php  /server-status  /info.php
/backup.zip  /www.zip  /site.tar.gz   (only the obvious names tied to the hostname)
```

`robots.txt` and `security.txt` are recon. Report them only when they point at a real exposure.

## Source maps

```bash
# Last line of a real bundle often is: //# sourceMappingURL=file.js.map  (or an absolute URL)
curl -sL "https://$TARGET/" | grep -oE 'src="[^"]+\.js"' 
# For each script URL, not a shell glob:
curl -sL "$JS_URL" | tail -c 200
curl -sL "${JS_URL}.map" -o /tmp/app.js.map
```

Next.js: build id is in the HTML (`/_next/static/<id>/`). Vite emits `/assets/index-<hash>.js`. Webpack manifests live at `asset-manifest.json`.

```python
import json, os
data = json.load(open("/tmp/app.js.map"))
os.makedirs("/tmp/sourcemap_extract", exist_ok=True)
for src, content in zip(data.get("sources") or [], data.get("sourcesContent") or []):
    if not content:
        continue
    rel = src.replace("webpack://", "").replace("../", "").replace("./", "").lstrip("/")
    path = os.path.join("/tmp/sourcemap_extract", rel)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w", errors="ignore").write(content)
```

Then search the tree for endpoints, `dangerouslySetInnerHTML`, `postMessage`, `firebaseConfig`, and **private** keys (see classification in `changed-js-deepdive`). `NEXT_PUBLIC_*` and Firebase `apiKey` are designed to ship. Source that only shows what the UI already calls is recon unless it reveals a hidden authz gap or a live secret.

## OpenAPI / Swagger

A real spec is JSON or YAML with `paths`. Extract paths and the write-models (`components.schemas`) — those field names are the mass-assignment list (`hunt-api-misconfig`). Swagger UI `?url=` / `?configUrl=` that loads an attacker spec is XSS only if you show script execution on that origin (CVE-2018-25031 class; version-gate the UI bundle). The spec being public is often intentional; the bug is an undocumented admin route that still runs without the admin check.

## `.git` and backups

`/.git/HEAD` containing `ref:` is step one. Confirm objects: `/.git/config`, then a `git-dumper` (or manual fetch of an object named in `/.git/index`). A HEAD you cannot follow into objects is a partial leak — say so. Scan history for secrets that are still valid; a rotated key in an old commit is informational once you show the live call fails.

`.DS_Store`: save the bytes, then parse. Do not pipe HTML into a DS_Store parser.

```bash
curl -sL "https://$TARGET/.DS_Store" -o /tmp/ds
file /tmp/ds    # "Apple Desktop Services Store" — not HTML
python3 -c "from ds_store import DSStore
for e in DSStore.open('/tmp/ds'):
    print(e.filename)"
```

Filenames inside are a wordlist for the next fetch, not a finding by themselves.

## Secrets — prove live, read-only

| Shape | Proof |
|---|---|
| AWS key | `aws sts get-caller-identity` with that key. Screenshot the account. One `s3 ls` or equivalent. Stop |
| Stripe `sk_live` / `sk_test` | One retrieve of your own test object or `/v1/balance`. Do not create charges |
| DB URL | Do not dump the database. A connect banner plus one metadata query is the ceiling, and only if the program allows |
| Generic bearer | One authenticated GET the key should not be able to make from the internet |
| Heap dump (`/actuator/heapdump`) | Strings for one live credential, then the read-only proof above. Do not attach the dump to a report |

Placeholder and `pk_` / `anon` keys: hunt the rule (`hunt-baas`), do not file the key.

## Validation

| Artifact | Finding | Not a finding |
|---|---|---|
| `.js.map` with `sourcesContent` | Hidden route, secret, or auth check you then hit | Minified duplicate of the public UI |
| OpenAPI | A path the spec lists that is weaker than the UI, proven with a request | The spec existing |
| `.env` / tfstate / `appsettings.json` | A secret that authenticates | `KEY=` empty or `example` |
| `.git` | Objects + a current secret or vulnerable logic you reproduce | `HEAD` only |
| `actuator/env` | Secret or internal host you use once | `build.version` alone (that is a lead) |
| `phpinfo` | Document root + a secret or an exploitable module version you actually use | The page with no follow-on |

Severity tracks the credential: working cloud/DB/admin secret is Critical; internal routes that still need auth are Medium until you bypass that auth; `robots.txt` is informational.

## Chains

- Map or spec → hidden admin route without the admin check → `hunt-api-owasp` API5.
- Spec schemas → extra JSON fields → mass assignment.
- `.git` history → removed `/debug` or a dependency pin → version-gated bug, then prove it.
- Source map `innerHTML` / `postMessage` → `hunt-dom` / `hunt-xss`.
- `firebaseConfig` / `supabase.co` → `hunt-baas`.
- `terraform.tfstate` / `.env` cloud key → `hunt-cloud-misconfig` (read-only).

## Rails

- In-scope hosts only. Do not crawl a guessed backup-file wordlist at brute-force scale; stick to names the app, vhost, and bundle already suggested.
- Do not use leaked credentials to write, pivot off-scope, or download a full database.
- Draft only — do not submit.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class source-leak --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the path or the still-valid secret is a differentiator.

Cross-refs: `changed-js-deepdive`, `hunt-api-misconfig`, `hunt-cloud-misconfig`, `hunt-baas`, `hunt-dom`.
