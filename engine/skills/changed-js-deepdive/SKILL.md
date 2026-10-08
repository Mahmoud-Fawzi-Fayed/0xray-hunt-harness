---
name: changed-js-deepdive
description: Turn a redeployed or newly-discovered JavaScript bundle into first-mover findings. Use when the novelty monitor flags a changed_js / new_js, when a target ships a new build, or whenever you spot a fresh JS bundle. A redeploy ships new API routes, new parameters, and sometimes leaked keys that nobody has hunted yet, so being first on the delta is the cleanest way to avoid duplicates. Wraps engine/jsdiff.py (diff two bundles into new endpoints/params/secrets/routes) and chains into the right hunt-* skill per candidate.
---

# changed-js-deepdive — hunt the delta of a redeployed bundle

A bundle whose hash just moved usually carries new code: an endpoint, a parameter, a feature flag, sometimes a secret. Diff the bundle and test the delta. Do not re-walk the whole app, and do not treat a string in a comment as a live route until you request it.

Trigger: `novelty.py` reports `changed_js` or `new_js`, or the HTML references a new `main.<hash>.js`, `/_next/static/<buildId>/`, `/assets/index-<hash>.js`, or `service-worker.js`.

## 1 — collect both sides

```bash
# Entry points: <script src>, importmap, asset-manifest.json, build-manifest
curl -sL "https://$TARGET/" | grep -oE 'src="[^"]+\.js"'
curl -sL "https://$TARGET/<bundle-url>" -o /tmp/new.js
```

Old copy, first one that exists: novelty cache, prior recon file, Wayback (`https://web.archive.org/web/<timestamp>/<bundle-url>`), or an older build id still linked from a cached HTML page. No old bytes at all:

```bash
python3 engine/jsdiff.py scan --new /tmp/new.js
```

With both versions:

```bash
python3 engine/jsdiff.py diff --old /tmp/old.js --new /tmp/new.js
python3 engine/jsdiff.py fetch --old "<OLD_URL>" --new "<NEW_URL>"
```

Buckets: `new_endpoints`, `new_params`, `new_secrets`, `new_routes`. If `//# sourceMappingURL=` or a sibling `.map` exists, reconstruct that module (`hunt-source-leak`) and read the new file, not the minified blob.

`jsdiff` string-buckets miss some env leaks. After the diff, grep **both** files for `import.meta.env`, `process.env.`, `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `Amplify.configure`, `identityPoolId`, `createServerReference(`. A newly bundled server-only value (`DATABASE_URL`, `SERVICE_ROLE`, `sk_live`) in client JS is `new_secrets` even if the tool did not label it.

Also diff, when the HTML itself changed: inline `<script>`, the service worker, and new chunk URLs the runtime loads (`import()`, webpack `chunkFilename`). A new chunk can hold the feature while `main.js` barely changed.

## 2 — priority

1. **`new_secrets`** — classify before testing.

   | Material | Action |
   |---|---|
   | `AKIA…`, `-----BEGIN`, `sk_live`, `ghp_`, `xox`, Supabase `service_role`, `x-hasura-admin-secret`, private cloud JSON | Read-only proof it is live (`sts get-caller-identity`, one scoped GET). Do not mutate, do not keep calling it |
   | Firebase `apiKey`, Stripe `pk_`, Supabase `anon`, OAuth client ids, Cognito pool ids | Not a secret. Hunt the **rule** behind them (`hunt-baas`, `hunt-cloud-misconfig`) |
   | High-entropy string that no API accepts | Drop it |

2. **`new_endpoints`** — request each as unauth, as user A, and as user B. New routes often ship without the check the old ones grew. `404` / SPA fallback identical to a random path = dead string, not a hidden API. Then pivot: object id in the path → `hunt-idor`; url/callback param → `hunt-ssrf` / `hunt-webhook`; query/body merged into an object → `hunt-api-misconfig`; `/graphql` → `hunt-graphql`; gRPC-web path → `hunt-grpc`.
3. **`new_params`** — hidden fields (`role`, `isAdmin`, `price`, `url`, `redirect`, `debug`, `tenant`). One mass-assignment or one SSRF OOB. Body-diff the saved object.
4. **`new_routes` (client routers)** — unreleased admin/debug UI. Map, then test the API the screen calls. The route existing in JS is recon, not a finding.
5. **New RPC / server-action ids on an old URL** — Next.js `createServerReference("…")` and `next-action` hashes, tRPC procedure names, Remix/React-Router action ids. The path can stay `/` while the sink is new. Request the new id as unauth, user A, and user B. An error byte-identical to a random id is a dead string. An authz gap or a new url/file parameter is `hunt-idor` / `hunt-ssrf` / `hunt-api-misconfig`.
6. **Changed auth logic on an old path** — if the diff shows a removed check, a new `dangerouslySetInnerHTML` / `innerHTML`, a `postMessage` handler, or a new `fetch(userUrl)`, test that sink even though the path is old (`hunt-xss`, `hunt-dom`, `hunt-ssrf`).

## 3 — prove, then dedup

Every candidate is request-proven. Unique marker in any payload. Two identities for authz. OOB for blind sinks.

```bash
python3 engine/dedup.py check --program <program> --class <cls> --url "<new endpoint>" --title "<title>"
```

`NOVEL` → `/validate` → draft. `LIKELY_DUP` → stop unless the new param, method, or bypass is a differentiator. A new bundle is not automatically a new bug.

## Rails

- In-scope bundles only. Secrets are read-only to verify.
- No keyspace guessing of unsigned URLs or tokens found in the diff. No DoS of a newly found expensive endpoint.
- Re-diff on the next redeploy; last week's delta is stale. Draft only — do not submit.

## Related

- `dedup-novelty` — fires this skill on `changed_js` / `new_js`.
- `hunt-source-leak` — `.map`, `.env`, spec files named in the new source.
- `hunt-idor`, `hunt-auth-bypass`, `hunt-api-misconfig` — new routes and params.
- `hunt-ssrf`, `hunt-xss`, `hunt-dom`, `hunt-graphql`, `hunt-baas` — sink-specific follow-up.
