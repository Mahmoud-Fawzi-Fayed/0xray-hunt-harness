---
name: hunt-api-owasp
description: "Triage map for the OWASP API Security Top 10 (2023) — API1 BOLA, API2 Broken Authentication, API3 BOPLA (mass assignment + excessive data exposure), API4 Unrestricted Resource Consumption, API5 BFLA, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management (shadow/old versions), API10 Unsafe Consumption of 3rd-party APIs. Distinct from OWASP Top 10 2025 (web). Use to systematically cover a JSON/REST/GraphQL API surface and pivot to the deeper hunt-* skill for each class. Umbrella methodology, not a replacement for the per-class skills."
sources: 0xray-authored
---

# HUNT-API-OWASP — OWASP API Security Top 10 (2023) triage map

Walk every row on every in-scope API. The 2023 list is still the current **OWASP API** Top 10. Do not remap these rows onto OWASP Top 10 **2025** (web: A01–A10) — that is a different document. GraphQL, gRPC, BaaS, and MCP/LLM tool APIs still walk this map; pivot skills cover depth, not a skipped row. This map does not replace the per-class skill.

## Inventory (do this once)

- Spec: `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/graphql`, `/.well-known/`, `asset-manifest.json`, JS bundles (`hunt-source-leak`, `changed-js-deepdive`).
- Versions and hosts: `/api/v1` vs `/v2` vs `/internal`, `staging.` / `dev.` / `beta.` — old versions are API9 and often miss a check the new one has.
- Two identities, A and B, before any authz test. Body-diff. Status codes lie (`200` with an empty list, `500` that still wrote).

## Decision tree

| Response you see | Try first | Class |
|---|---|---|
| Object id in a path, query, JSON body, GraphQL variable, or a batch/array | Replay as A with B's id, including one `{"ids":["ID_B"]}` | API1 |
| `401` missing, or JWT in `Authorization` / cookie | Drop the token; flip `alg`; call as the other user | API2 |
| JSON has `role`, `is_admin`, `email`, `balance`, fields the UI never shows | Add those fields on write; read a list endpoint | API3 |
| `limit` / `page_size` / GraphQL `first` echoes your number | One large **capped** read (e.g. 1000) | API4 |
| `/admin`, verb `PUT`/`DELETE`, or `action=export` works as a normal user | Same request as a fresh low-priv user | API5 |
| Coupon, invite, checkout, transfer, vote | One logic abuse (`hunt-business-logic`) | API6 |
| Field named `url`, `callback`, `avatar`, `feed`, `file` | OOB URL, then one metadata URL | API7 |
| Stack trace, `Access-Control-Allow-Origin: <your origin>`, `/debug`, default creds in a spec | Confirm data leaves the browser or the debug route returns secrets | API8 |
| Path only in an old bundle or `/v1` | Hit it with A's token | API9 |
| The API stores a URL it later fetches from a partner, or trusts a webhook body | `hunt-webhook` / `hunt-ssrf` | API10 |

## The ten checks

| # | Class | One request | Proves it | Go deeper |
|---|---|---|---|---|
| API1 | **BOLA** | `GET /api/orders/ID_B` as A, or the same id in a JSON/GraphQL body | Body contains B's fields A cannot see in the UI. One extra id in a batch, then stop | `hunt-idor` |
| API2 | **Broken auth** | Same call with no token, `alg:none`, or A's token on B's action. Magic-link host poison and passkey enroll are the same class | Unauthorized object read, state change, or a session as B | `hunt-auth-bypass`, `hunt-jwt`, `hunt-mfa-bypass`, `hunt-ato` |
| API3 | **BOPLA** | `PATCH /me {"role":"admin","verified":true}` and `GET /users?limit=1` | Role sticks on re-read, or response includes another user's secret field | `hunt-api-misconfig` |
| API4 | **Resource use** | `?limit=1000` or a 5-alias GraphQL query once | Server returns far more than the business cap, or skips authz when batched | `hunt-graphql` — do not load the origin |
| API5 | **BFLA** | Low-priv user calls `POST /admin/...` or `X-HTTP-Method-Override: DELETE` | Privileged state change or admin-only data | `hunt-idor`, `hunt-api-misconfig` |
| API6 | **Business flow** | Skip a step, negative qty, replay a webhook, race one coupon | Persisted money/entitlement/state is wrong | `hunt-business-logic`, `hunt-race-condition` |
| API7 | **SSRF** | `url=https://<rand>.<oob>/` then one `169.254.169.254` URL | OOB hit or internal body | `hunt-ssrf`, `hunt-webhook` |
| API8 | **Misconfig** | Spec, CORS preflight, verbose error, debug route | Sensitive data actually obtained, not a header in isolation | `hunt-cors`, `hunt-api-misconfig`, `hunt-source-leak` |
| API9 | **Inventory** | Request a path that exists only in an old JS bundle or `/v0` | It still authorizes differently from current `/v2` | `changed-js-deepdive`, `hunt-source-leak` |
| API10 | **Unsafe consumption** | Callback or import URL the server fetches for a partner (PSP webhook, MCP/LLM tool result, SaaS import) | Forged partner body changes state, or the fetch hits metadata | `hunt-webhook`, `hunt-ssrf`, `hunt-mcp` |

API2 rate-limit notes: a missing limit is reportable when a **small** sample (about 10) of a sensitive action all succeed and the program cares about that control. Do not guess passwords, OTPs, or API keys. No credential stuffing.

API4: one oversized read or one batch that bypasses a cost/authz check. Stop. Do not stream until the process falls over.

## Validation (every row)

- **Body-diff** A vs B, and before vs after. A `200` that matches the unauthenticated error page is a miss.
- **ID source:** a single BOLA hit on a UUIDv4 you were handed is real but not "the whole table" unless you show how the next id is obtained (a list endpoint, a predictable id, an object you can enumerate). Say which.
- **Blind classes** (SSRF, stored XSS, outbound webhooks) need OOB with a unique marker. Timing claims need n≥10 paired samples, not one slow response.
- **Re-read** after a write. Mass assignment and BFLA are whatever `GET` returns after the `PATCH`, not the `PATCH` body echoing your input.

## Rails

- In-scope hosts only. Read-only by default; the single write in the table is the proof, then stop.
- No brute-force, no DoS, no mass export of user tables.
- Draft only — do not submit. Dedup with the **specific** class you proved (`idor`, `ssrf`, `auth-bypass`, …), not `api`.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class idor --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless endpoint, param, or a fix bypass is a concrete differentiator.

Cross-refs: `hunt-idor`, `hunt-auth-bypass`, `hunt-jwt`, `hunt-api-misconfig`, `hunt-ssrf`, `hunt-webhook`, `hunt-graphql`, `hunt-grpc`, `hunt-baas`, `hunt-business-logic`, `hunt-mcp`, `triage-validation`.
