---
name: hunt-api-owasp
description: "Triage map for the OWASP API Security Top 10 (2023) — API1 BOLA, API2 Broken Authentication, API3 BOPLA (mass assignment + excessive data exposure), API4 Unrestricted Resource Consumption, API5 BFLA, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management (shadow/old versions), API10 Unsafe Consumption of 3rd-party APIs. Use to systematically cover a JSON/REST/GraphQL API surface and pivot to the deeper hunt-* skill for each class. Umbrella methodology, not a replacement for the per-class skills."
sources: 0xray-authored
---

# HUNT-API-OWASP — OWASP API Security Top 10 (2023) triage map

Use this as the **coverage checklist** for any JSON/REST/GraphQL API: walk each item, and on a hit
pivot to the deeper `hunt-*` skill named in the "Go deeper" column. It exists to stop you
tunnel-visioning on one class and leaving the rest of the API surface untested.

## First — inventory the surface
- Pull the spec: `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/graphql` (introspection),
  `/.well-known/`, `asset-manifest.json`, and JS bundles (see `hunt-source-leak`,
  `changed-js-deepdive`).
- Enumerate **versions and environments**: `/api/v1` vs `/v2` vs `/internal`, and
  `staging.` / `dev.` / `beta.` hosts — old and shadow versions are API9.

## The Top 10 — what to test, where to go deeper
| # | Class | Quick test | Go deeper |
|---|---|---|---|
| API1 | **BOLA** (object-level authz) | swap `id`/`uuid`/`slug` across two identities; body-diff | `hunt-idor` |
| API2 | **Broken authentication** | missing/expired/forged token; weak JWT; reset/OTP flaws | `hunt-auth-bypass`, `hunt-jwt`, `hunt-mfa-bypass` |
| API3 | **BOPLA** (mass assignment + excessive data) | POST extra fields (`is_admin`, `role`, `verified`); scan responses for over-returned PII | `hunt-api-misconfig` |
| API4 | **Unrestricted resource consumption** | no rate limit / no pagination cap / huge `limit`; expensive GraphQL | `hunt-brute-force`, `hunt-graphql` |
| API5 | **BFLA** (function-level authz) | call admin/privileged methods as a low-priv user; HTTP verb tampering | `hunt-idor`, `hunt-api-misconfig` |
| API6 | **Sensitive business flows** | automate a flow meant to be rate/human-gated (checkout, invite, signup) | `hunt-business-logic` |
| API7 | **SSRF** | user-supplied URL (webhook, import, link-preview, PDF render) -> internal/metadata | `hunt-ssrf`, `hunt-webhook` |
| API8 | **Security misconfiguration** | verbose errors, permissive CORS, authz missing on `OPTIONS`, debug endpoints, default creds | `hunt-cors`, `hunt-api-misconfig`, `hunt-source-leak` |
| API9 | **Improper inventory** | shadow/old API versions, undocumented hosts, deprecated-but-live endpoints | `hunt-source-leak`, `changed-js-deepdive` |
| API10 | **Unsafe consumption of 3rd-party APIs** | the API blindly trusts an upstream/partner response -> injection/SSRF via that channel | `hunt-ssrf`, `hunt-api-misconfig` |

## Discipline
- Use **two identities (A, B)** for every authz test; **body-diff**, never trust status codes alone.
- For SSRF and other blind classes, require **OOB confirmation** (see the specific skill's gate).
- **Severity honesty**: a single cross-account read via a random UUIDv4 is AC:H / Medium, not a
  "mass breach" — you must demonstrate a way to obtain other users' IDs to scale it. See
  `triage-validation`.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding, run the dedup gate with the **specific** class you
landed (`idor`, `ssrf`, `auth-bypass`, ...), e.g.:

```bash
python3 engine/dedup.py check --program <program> --class idor --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).

Cross-references: `hunt-idor`, `hunt-auth-bypass`, `hunt-jwt`, `hunt-api-misconfig`, `hunt-ssrf`,
`hunt-webhook`, `hunt-graphql`, `hunt-business-logic`, `triage-validation`, `dedup-novelty`.
